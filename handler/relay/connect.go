package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
	sx "github.com/go-gost/x/internal/util/selector"
	serial_util "github.com/go-gost/x/internal/util/serial"
	goserial "github.com/tarm/serial"
)

func (h *relayHandler) handleConnect(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) (err error) {
	if network == "unix" || network == "serial" {
		if host, _, _ := net.SplitHostPort(address); host != "" {
			address = host
		}
	}

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
		err = errors.New("target not specified")
		log.Error(err)
		return
	}

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, network, address) {
		log.Debug("bypass: ", address)
		resp.Status = relay.StatusForbidden
		_, err = resp.WriteTo(conn)
		return
	}

	switch h.md.hash {
	case "host":
		ctx = sx.ContextWithHash(ctx, &sx.Hash{Source: address})
	}

	var cc io.ReadWriteCloser

	switch network {
	case "unix":
		cc, err = (&net.Dialer{}).DialContext(ctx, "unix", address)
	case "serial":
		cc, err = goserial.OpenPort(serial_util.ParseConfigFromAddr(address))
	default:
		cc, err = h.router.Dial(ctx, network, address)
	}
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
