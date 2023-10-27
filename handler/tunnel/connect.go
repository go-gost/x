package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
)

func (h *tunnelHandler) handleConnect(ctx context.Context, conn net.Conn, network, srcAddr string, dstAddr string, tunnelID relay.TunnelID, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst":    fmt.Sprintf("%s/%s", dstAddr, network),
		"cmd":    "connect",
		"tunnel": tunnelID.String(),
	})

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, network, dstAddr) {
		log.Debug("bypass: ", dstAddr)
		resp.Status = relay.StatusForbidden
		_, err := resp.WriteTo(conn)
		return err
	}

	host, _, _ := net.SplitHostPort(dstAddr)

	// client is a public entrypoint.
	if tunnelID.Equal(h.md.entryPointID) && !h.md.entryPointID.IsZero() {
		resp.WriteTo(conn)
		return h.ep.handle(ctx, conn)
	}

	var tid relay.TunnelID
	if ingress := h.md.ingress; ingress != nil && host != "" {
		tid = parseTunnelID(ingress.Get(ctx, host))
	}

	// direct routing
	if h.md.directTunnel {
		tid = tunnelID
	} else if !tid.Equal(tunnelID) {
		resp.Status = relay.StatusHostUnreachable
		resp.WriteTo(conn)
		err := fmt.Errorf("no route to host %s", host)
		log.Error(err)
		return err
	}

	cc, _, err := getTunnelConn(network, h.pool, tid, 3, log)
	if err != nil {
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		log.Error(err)
		return err
	}
	defer cc.Close()

	log.Debugf("%s >> %s", conn.RemoteAddr(), cc.RemoteAddr())

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

	resp.WriteTo(cc)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}
