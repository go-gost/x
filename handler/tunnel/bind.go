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
// The bind address host is resolved as follows:
//  1. If the user supplied a host (e.g. "dash" from "dash:8081") AND
//     ingress is configured, use that host directly — the tunnel is
//     reachable via the user's custom name.
//  2. Before using the custom host, check for ingress conflicts: if
//     another tunnel already owns this hostname, fall back to the
//     md5 hash to avoid route hijacking.
//  3. If no host was supplied (e.g. ":8081") or ingress is nil, use
//     the deterministic md5 hash of tunnelID as a stable ingress key.
//
// Flow:
//  1. Generate a random connector ID (copies weight from tunnelID).
//  2. Resolve the response address host per the rules above.
//  3. Send relay response with the bind address + tunnel features back.
//  4. Upgrade the TCP connection to a mux.ClientSession (smux).
//  5. Create a Connector wrapping the mux session.
//  6. Register:
//     a. Add Connector to ConnectorPool (under tunnelID).
//     b. Set ingress rules: the resolved host → tunnelID. When the user
//        supplied a custom host that differs from the hash, also set a
//        fallback rule: hash → tunnelID.
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
	if host == "" || isUnspecified(host) || h.md.ingress == nil {
		host = endpoint
	} else if host != endpoint {
		if rule := h.md.ingress.GetRule(ctx, host, ingress.WithService(h.options.Service)); rule != nil && rule.Endpoint != tunnelID.String() {
			host = endpoint
		}
	}
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
		if host != "" && host != endpoint {
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

// isUnspecified reports whether the host is an unspecified IP address
// (0.0.0.0 or ::) that should be treated the same as an empty host.
func isUnspecified(host string) bool {
	return host == "0.0.0.0" || host == "::"
}
