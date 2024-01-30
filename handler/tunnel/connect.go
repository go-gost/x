package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/limiter/traffic/wrapper"
)

func (h *tunnelHandler) handleConnect(ctx context.Context, req *relay.Request, conn net.Conn, network, srcAddr string, dstAddr string, tunnelID relay.TunnelID, log logger.Logger) error {
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
	if tunnelID.Equal(h.md.entryPointID) {
		resp.WriteTo(conn)
		return h.ep.handle(ctx, conn)
	}

	if !h.md.directTunnel {
		var tid relay.TunnelID
		if ingress := h.md.ingress; ingress != nil && host != "" {
			if rule := ingress.GetRule(ctx, host); rule != nil {
				tid = parseTunnelID(rule.Endpoint)
			}
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
		node:    h.id,
		pool:    h.pool,
		sd:      h.md.sd,
		retry:   3,
		timeout: 15 * time.Second,
		log:     log,
	}
	cc, node, cid, err := d.Dial(ctx, network, tunnelID.String())
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	log.Debugf("new connection to tunnel: %s, connector: %s", tunnelID, cid)

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

		resp.WriteTo(cc)
	} else {
		req.WriteTo(cc)
	}

	rw := wrapper.WrapReadWriter(h.options.Limiter, conn,
		traffic.NetworkOption(network),
		traffic.AddrOption(dstAddr),
		traffic.ClientOption(string(ctxvalue.ClientIDFromContext(ctx))),
		traffic.SrcOption(conn.RemoteAddr().String()),
	)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}
