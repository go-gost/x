package tunnel

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/google/uuid"
)

// handleBind handles a CmdBind request from an internal client.
//
// Flow:
//  1. Generate a random connector ID (copies weight from tunnelID).
//  2. Compute an 8-hex-char endpoint from md5(tunnelID) for ingress routing.
//  3. Send relay response with address + tunnel features back to client.
//  4. Upgrade the TCP connection to a mux.ClientSession (smux).
//  5. Create a Connector wrapping the mux session.
//  6. Register:
//     a. Add Connector to ConnectorPool (under tunnelID).
//     b. If ingress is configured, set rules: endpoint → tunnelID, and
//        the bind address host → tunnelID.
//     c. If SD is configured, register the service (tunnelID, node, network).
//
// The mux session ownership is transferred to the Connector — conn is NOT
// closed after this function returns (no defer conn.Close()). The Connector's
// waitClose goroutine handles session lifecycle.
func (h *tunnelHandler) handleBind(ctx context.Context, conn net.Conn, network, address string, tunnelID relay.TunnelID, log logger.Logger) (err error) {
	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	uuid, err := uuid.NewRandom()
	if err != nil {
		resp.Status = relay.StatusInternalServerError
		resp.WriteTo(conn)
		return
	}
	connectorID := relay.NewConnectorID(uuid[:])
	if network == "udp" {
		connectorID = relay.NewUDPConnectorID(uuid[:])
	}
	// copy weight from tunnelID
	connectorID = connectorID.SetWeight(tunnelID.Weight())

	v := md5.Sum([]byte(tunnelID.String()))
	endpoint := hex.EncodeToString(v[:8])

	host, port, _ := net.SplitHostPort(address)
	// Always use the endpoint hash as the host — this provides a stable,
	// deterministic ingress key regardless of what the internal client sends.
	// The original host is ignored; the endpoint hash routes consistently
	// across reconnects and multi-node deployments.
	host = endpoint
	addr := net.JoinHostPort(host, port)

	af := &relay.AddrFeature{}
	err = af.ParseFrom(addr)
	if err != nil {
		log.Warn(err)
	}
	resp.Features = append(resp.Features, af,
		&relay.TunnelFeature{
			ID: connectorID,
		},
	)
	if _, err = resp.WriteTo(conn); err != nil {
			log.Error(err)
			return
		}

		// Upgrade connection to multiplex session.
	session, err := mux.ClientSession(conn, h.md.muxCfg)
	if err != nil {
		return
	}

	var stats stats.Stats
	if h.stats != nil {
		stats = h.stats.Stats(tunnelID.String())
	}

	c := NewConnector(connectorID, tunnelID, h.id, session, &ConnectorOptions{
		service: h.options.Service,
		sd:      h.md.sd,
		stats:   stats,
		limiter: h.limiter,
	})

	h.pool.Add(tunnelID, c, h.md.tunnelTTL)
	if h.md.ingress != nil {
		h.md.ingress.SetRule(ctx, &ingress.Rule{
			Hostname: endpoint,
			Endpoint: tunnelID.String(),
		}, ingress.WithService(h.options.Service))
		if host != "" {
			h.md.ingress.SetRule(ctx, &ingress.Rule{
				Hostname: host,
				Endpoint: tunnelID.String(),
			}, ingress.WithService(h.options.Service))
		}
	}
	if h.md.sd != nil {
		err := h.md.sd.Register(ctx, &sd.Service{
			ID:      connectorID.String(),
			Name:    tunnelID.String(),
			Node:    h.id,
			Network: network,
			Address: h.md.entryPoint,
		})
		if err != nil {
			h.log.Error(err)
		}
	}

	log.Debugf("%s/%s: tunnel=%s, connector=%s, weight=%d established", addr, network, tunnelID, connectorID, connectorID.Weight())

	return
}
