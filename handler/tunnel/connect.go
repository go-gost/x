package tunnel

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
)

func (h *tunnelHandler) handleConnect(ctx context.Context, conn net.Conn, network, address string, tunnelID relay.TunnelID, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst":    fmt.Sprintf("%s/%s", address, network),
		"cmd":    "connect",
		"tunnel": tunnelID.String(),
	})

	log.Debugf("%s >> %s/%s", conn.RemoteAddr(), address, network)

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	host, sp, _ := net.SplitHostPort(address)

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, network, address) {
		log.Debug("bypass: ", address)
		resp.Status = relay.StatusForbidden
		_, err := resp.WriteTo(conn)
		return err
	}

	var tid relay.TunnelID
	if ingress := h.md.ingress; ingress != nil {
		tid = parseTunnelID(ingress.Get(ctx, host))
	}

	// client is not an public entrypoint.
	if h.md.entryPointID.IsZero() || !tunnelID.Equal(h.md.entryPointID) {
		if !tid.Equal(tunnelID) && !h.md.directTunnel {
			resp.Status = relay.StatusHostUnreachable
			resp.WriteTo(conn)
			err := fmt.Errorf("no route to host %s", host)
			log.Error(err)
			return err
		}
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

	rc := &tcpConn{
		Conn: conn,
	}
	// cache the header
	if _, err := resp.WriteTo(&rc.wbuf); err != nil {
		return err
	}
	conn = rc

	var features []relay.Feature
	af := &relay.AddrFeature{} // source/visitor address
	af.ParseFrom(conn.RemoteAddr().String())
	features = append(features, af)

	if host != "" {
		port, _ := strconv.Atoi(sp)
		// target host
		af = &relay.AddrFeature{
			AType: relay.AddrDomain,
			Host:  host,
			Port:  uint16(port),
		}
		features = append(features, af)
	}

	resp = relay.Response{
		Version:  relay.Version1,
		Status:   relay.StatusOK,
		Features: features,
	}
	resp.WriteTo(cc)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}
