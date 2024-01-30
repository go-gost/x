package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	serial "github.com/go-gost/x/internal/util/serial"
	"github.com/go-gost/x/limiter/traffic/wrapper"
	"github.com/go-gost/x/stats"
	stats_wrapper "github.com/go-gost/x/stats/wrapper"
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
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: address})
	}

	var cc io.ReadWriteCloser

	switch network {
	case "unix":
		cc, err = (&net.Dialer{}).DialContext(ctx, "unix", address)
	case "serial":
		cc, err = serial.OpenPort(serial.ParseConfigFromAddr(address))
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

	clientID := ctxvalue.ClientIDFromContext(ctx)
	rw := wrapper.WrapReadWriter(h.options.Limiter, conn,
		traffic.NetworkOption(network),
		traffic.AddrOption(address),
		traffic.ClientOption(string(clientID)),
		traffic.SrcOption(conn.RemoteAddr().String()),
	)
	if h.options.Observer != nil {
		pstats := h.stats.Stats(string(clientID))
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
		rw = stats_wrapper.WrapReadWriter(rw, pstats)
	}

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), address)
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), address)

	return nil
}
