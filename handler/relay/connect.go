package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	netpkg "github.com/go-gost/x/internal/net"
	sx "github.com/go-gost/x/internal/util/selector"
)

func (h *relayHandler) handleConnect(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", address, network),
		"cmd": "connect",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), address)

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

	if h.options.Bypass != nil && h.options.Bypass.Contains(address) {
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
	log.Debugf("%s <-> %s", conn.RemoteAddr(), address)
	netpkg.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), address)

	return nil
}
