package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
	sx "github.com/go-gost/x/internal/util/selector"
)

func (h *relayHandler) handleConnect(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", address, network),
		"cmd": "connect",
	})

	log.Debugf("%s >> %s/%s", conn.RemoteAddr(), address, network)

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if address == "" {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		err := errors.New("target not specified")
		log.Error(err)
		return err
	}

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, address) {
		log.Debug("bypass: ", address)
		resp.Status = relay.StatusForbidden
		_, err := resp.WriteTo(conn)
		return err
	}

	switch h.md.hash {
	case "host":
		ctx = sx.ContextWithHash(ctx, &sx.Hash{Source: address})
	}
	cc, err := h.router.Dial(ctx, network, address)
	if err != nil {
		resp.Status = relay.StatusNetworkUnreachable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	if h.md.noDelay {
		if _, err := resp.WriteTo(conn); err != nil {
			log.Error(err)
			return err
		}
	}

	switch network {
	case "udp", "udp4", "udp6":
		rc := &udpConn{
			Conn: conn,
		}
		if !h.md.noDelay {
			// cache the header
			if _, err := resp.WriteTo(&rc.wbuf); err != nil {
				return err
			}
		}
		conn = rc
	default:
		if !h.md.noDelay {
			rc := &tcpConn{
				Conn: conn,
			}
			// cache the header
			if _, err := resp.WriteTo(&rc.wbuf); err != nil {
				return err
			}
			conn = rc
		}
	}

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), address)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), address)

	return nil
}

func (h *relayHandler) handleConnectTunnel(ctx context.Context, conn net.Conn, network, address string, tunnelID relay.TunnelID, log logger.Logger) error {
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

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, address) {
		log.Debug("bypass: ", address)
		resp.Status = relay.StatusForbidden
		_, err := resp.WriteTo(conn)
		return err
	}

	var tid relay.TunnelID
	if ingress := h.md.ingress; ingress != nil {
		tid = parseTunnelID(ingress.Get(ctx, host))
	}
	if !tid.Equal(tunnelID) && !h.md.directTunnel {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		err := fmt.Errorf("not route to host %s", host)
		log.Error(err)
		return err
	}

	cc, _, err := getTunnelConn(network, h.pool, tunnelID, 3, log)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	log.Debugf("%s >> %s", conn.RemoteAddr(), cc.RemoteAddr())

	if h.md.noDelay {
		if _, err := resp.WriteTo(conn); err != nil {
			log.Error(err)
			return err
		}
	} else {
		rc := &tcpConn{
			Conn: conn,
		}
		// cache the header
		if _, err := resp.WriteTo(&rc.wbuf); err != nil {
			return err
		}
		conn = rc
	}

	var features []relay.Feature
	af := &relay.AddrFeature{} // visitor address
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
