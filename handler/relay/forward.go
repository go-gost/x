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
)

func (h *relayHandler) handleForward(ctx context.Context, conn net.Conn, network string, log logger.Logger) error {
	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}
	target := h.hop.Select(ctx)
	if target == nil {
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", target.Addr, network),
		"cmd": "forward",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

	cc, err := h.router.Dial(ctx, network, target.Addr)
	if err != nil {
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}

		resp.Status = relay.StatusHostUnreachable
		resp.WriteTo(conn)
		log.Error(err)

		return err
	}
	defer cc.Close()
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

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
		rc := &tcpConn{
			Conn: conn,
		}
		if !h.md.noDelay {
			// cache the header
			if _, err := resp.WriteTo(&rc.wbuf); err != nil {
				return err
			}
		}
		conn = rc
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), target.Addr)
	netpkg.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}
