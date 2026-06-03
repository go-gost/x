package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleForward processes relay forward mode.
//
// When a hop is set on the relayHandler (via Forward()), this mode is used.
// Unlike handleConnect, the target address is not specified by the client;
// instead it is selected by the hop's load-balancing strategy (round-robin,
// random, hash, etc.).
//
// Data flow:
//
//	handleForward()
//	├─ 1. hop.Select() picks a target node from the hop
//	│   └─ No node available → return ServiceUnavailable
//	├─ 2. Wrap traffic limiter + stats
//	├─ 3. Router.Dial() dials the target node
//	│   └─ Dial fails → mark the node (Mark()) → return HostUnreachable
//	├─ 4. On success, reset the node's failure marker
//	├─ 5. Send response header (noDelay controls timing)
//	├─ 6. Wrap connection by network type (tcpConn/udpConn)
//	└─ 7. xnet.Pipe() bidir data copy (client ↔ target)
//
// Failure handling:
//   - If Router.Dial fails and the target node has a Marker, the node is
//     marked as failed. Marked nodes are skipped by FailFilter/BackupFilter
//     in subsequent selections.
//   - On successful dial, the marker is reset, indicating recovery.
func (h *relayHandler) handleForward(ctx context.Context, conn net.Conn, network string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
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
		"dst": target.Addr,
		"cmd": "forward",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

	// --- Traffic limiter + stats wrapper ---
	{
		clientID := ctxvalue.ClientIDFromContext(ctx)
		rw := wrapper.WrapReadWriter(
			h.limiter,
			conn,
			string(clientID),
			limiter.ServiceOption(h.options.Service),
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.NetworkOption(network),
			limiter.AddrOption(target.Addr),
			limiter.ClientOption(string(clientID)),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(string(clientID))
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}
		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	// Dial the target node, recording the route path.
	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, target.Addr)
	ro.Route = buf.String()
	if err != nil {
		// TODO: the router itself may fail because of a failed node in the route.
		// Marking the node here may be incorrect in that case.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}

		resp.Status = relay.StatusHostUnreachable
		resp.WriteTo(conn)
		log.Error(err)

		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	// Reset the failure marker on successful dial.
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	// --- Send response header ---
	if h.md.noDelay {
		if _, err := resp.WriteTo(conn); err != nil {
			log.Error(err)
			return err
		}
	}

	// --- Wrap connection by network type ---
	switch network {
	case "udp", "udp4", "udp6":
		rc := &udpConn{
			Conn: conn,
		}
		if !h.md.noDelay {
			// Buffer the response header, merged with the first data packet.
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
			// Buffer the response header, merged with the first data packet.
			if _, err := resp.WriteTo(&rc.wbuf); err != nil {
				return err
			}
		}
		conn = rc
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}