package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
)

// handleConnect handles a CmdConnect request.
//
// This is the "pull" path: a public user's connection arrives via the tunnel
// handler's listener, and the handler creates a stream into the tunnel to
// reach the internal service.
//
// Flow:
//  1. Bypass check against dstAddr.
//  2. Ingress routing: if the tunnel is the public entryPointID, look up the
//     destination host in the ingress table to find the target tunnel ID.
//     For direct tunnels, the tunnelID from the request is used directly.
//  3. Dialer.Dial() → pool.Get() → GetConn() → mux.OpenStream()
//     (or SD fallback if no local connector).
//  4. Relay protocol framing:
//     a. Local node (node == h.id): write StatusOK response to the public
//        connection, then write a StatusOK response with src/dst address
//        features to the mux stream. The internal client uses these address
//        features to know where to connect.
//     b. Remote node (SD fallback): write the original relay request
//        directly to the mux stream for the remote node to process.
//  5. Pipe(publicConn, muxStream) — bidirectional data relay until either
//     side closes.
//
// The mux stream (cc) is closed via defer cc.Close() when this function
// returns. The public connection (conn) is closed by the caller's
// defer conn.Close() in Handle().
func (h *tunnelHandler) handleConnect(ctx context.Context, req *relay.Request, conn net.Conn, network, srcAddr string, dstAddr string, tunnelID relay.TunnelID, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst":    fmt.Sprintf("%s/%s", dstAddr, network),
		"cmd":    "connect",
		"tunnel": tunnelID.String(),
		"host":   dstAddr,
	})

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, network, dstAddr, bypass.WithService(h.options.Service)) {
		log.Debug("bypass: ", dstAddr)
		resp.Status = relay.StatusForbidden
		_, err := resp.WriteTo(conn)
		return fmt.Errorf("bypass blocked %s: %w", dstAddr, err)
	}

	host, _, _ := net.SplitHostPort(dstAddr)

	var tid relay.TunnelID
	if ing := h.md.ingress; ing != nil && host != "" {
		if rule := ing.GetRule(ctx, host, ingress.WithService(h.options.Service)); rule != nil {
			tid = ParseTunnelID(rule.Endpoint)
		}
	}

	// visitor is a public entrypoint.
	if tunnelID.Equal(h.md.entryPointID) {
		if tid.IsZero() {
			resp.Status = relay.StatusNetworkUnreachable
			resp.WriteTo(conn)
			err := fmt.Errorf("no route to host %s", host)
			log.Error(err)
			return err
		}

		if tid.IsPrivate() {
			resp.Status = relay.StatusHostUnreachable
			resp.WriteTo(conn)
			err := fmt.Errorf("tunnel %s is private for host %s", tid, host)
			log.Error(err)
			return err
		}
	} else {
		// direct routing
		if h.md.directTunnel {
			tid = tunnelID
		}
		if !tid.Equal(tunnelID) {
			resp.Status = relay.StatusHostUnreachable
			resp.WriteTo(conn)
			err := fmt.Errorf("no route to host %s", host)
			log.Error(err)
			return err
		}
	}

	d := Dialer{
		Node:    h.id,
		Pool:    h.pool,
		SD:      h.md.sd,
		Retry:   3,
		Timeout: 15 * time.Second,
		Log:     log,
	}
	cc, node, cid, err := d.Dial(ctx, network, tid.String())
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	log.Debugf("connect to node=%s tunnel=%s connector=%s OK", node, tid, cid)

	if node == h.id {
		if _, err := resp.WriteTo(conn); err != nil {
			log.Error(err)
			return err
		}

		resp = relay.Response{
			Version: relay.Version1,
			Status:  relay.StatusOK,
		}

		af := &relay.AddrFeature{}
		af.ParseFrom(srcAddr)
		resp.Features = append(resp.Features, af) // src address

		af = &relay.AddrFeature{}
		af.ParseFrom(dstAddr)
		resp.Features = append(resp.Features, af) // dst address

		if _, err := resp.WriteTo(cc); err != nil {
			log.Error(err)
			cc.Close()
			return err
		}
	} else {
		if _, err := req.WriteTo(cc); err != nil {
			log.Error(err)
			cc.Close()
			return err
		}
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	// xnet.Transport(conn, cc)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}
