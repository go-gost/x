package local

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"

	quicdissector "github.com/go-gost/quic-dissector"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/bypass"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/sniffing"
	xrecorder "github.com/go-gost/x/recorder"
)

// dialResult is returned by dialTarget, carrying the dialed connection
// and associated state that callers need for subsequent I/O and logging.
type dialResult struct {
	cc     net.Conn
	log    logger.Logger
	target *chain.Node
}

// dialTarget performs node selection, Router.Dial, proxy protocol wrapping,
// and recorder population — the shared preamble for both stream forwarding
// (handleRawForwarding) and datagram forwarding (handleRawDatagram).
//
// The caller must close cc when done.
func (h *forwardHandler) dialTarget(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, network, proto string) (*dialResult, error) {
	target := &chain.Node{}
	if curHop := h.getHop(); curHop != nil {
		target = curHop.Select(ctx,
			hop.ProtocolSelectOption(proto),
		)
	}
	if target == nil {
		log.Error(errNodeNotAvailable)
		return nil, errNodeNotAvailable
	}
	ro.Node = target.Name
	addr := target.Addr
	if opts := target.Options(); opts != nil {
		if opts.Network != "" {
			network = opts.Network
		}
	}
	if network != "unix" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr += ":0"
		}
	}

	ro.Network = network
	ro.Host = addr

	log = log.WithFields(map[string]any{
		"node":    target.Name,
		"dst":     addr,
		"network": network,
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, addr)
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return nil, err
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	cc = proxyproto.WrapClientConn(
		h.md.proxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		cc)

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	return &dialResult{
		cc:     cc,
		log:    log,
		target: target,
	}, nil
}

// handleRawForwarding performs node selection, dials the target through the
// router, and pipes the raw connection. It is used when sniffing is disabled
// or the protocol was not HTTP/TLS.
// When proto is "quic" and clientDgram is set, the first upstream datagram is
// intercepted to parse the TLS ServerHello, then threaded back via
// io.MultiReader before the pipe.
func (h *forwardHandler) handleRawForwarding(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, network, proto string, clientDgram []byte) error {
	dr, err := h.dialTarget(ctx, conn, ro, log, network, proto)
	if err != nil {
		return err
	}
	defer dr.cc.Close()

	// QUIC ServerHello sniff from upstream response.
	if proto == sniffing.ProtoQUIC && ro.TLS != nil {
		if h.md.sniffingTimeout > 0 {
			dr.cc.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		sdgram := make([]byte, h.md.bufferSize)
		n, readErr := dr.cc.Read(sdgram)

		if h.md.sniffingTimeout > 0 {
			dr.cc.SetReadDeadline(time.Time{})
		}

		if readErr != nil {
			dr.log.Debugf("udp server sniff read: %v", readErr)
		}
		if n > 0 {
			sdgram = sdgram[:n]
			if sh, shErr := quicdissector.SniffQUICServerHello(clientDgram, sdgram); shErr == nil {
				sniffing.PopulateQUICServerHello(sh, ro)
			}
			dr.cc = xnet.NewReadWriteConn(io.MultiReader(bytes.NewReader(sdgram), dr.cc), dr.cc, dr.cc)
		}
	}

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), dr.target.Addr)
	if err := xnet.Pipe(ctx, conn, dr.cc, xnet.WithReadTimeout(h.md.idleTimeout)); err != nil {
		log.Debugf("pipe: %v", err)
	}
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), dr.target.Addr)

	return nil
}

// handleRawDatagram forwards a single UDP datagram to the selected node and
// writes the response back. Unlike handleRawForwarding (which uses xnet.Pipe
// for bidirectional stream copy), this performs a single request-response
// cycle — appropriate for stateless UDP forwarding where each packet is
// independent and no session is maintained.
//
// The method reuses dialTarget for the shared hop-selection, Router.Dial,
// proxyproto, and recorder preamble.
func (h *forwardHandler) handleRawDatagram(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, network string) error {
	bufp := make([]byte, h.md.bufferSize)
	n, err := conn.Read(bufp)
	if err != nil {
		log.Debugf("conn read: %v", err)
		return err
	}
	clientDgram := bufp[:n]

	if h.md.sniffing {
		if info, sniffErr := quicdissector.SniffQUIC(clientDgram); sniffErr == nil {
			sniffing.PopulateQUICClientHello(clientDgram, info, ro)

			if info.ServerName != "" {
				ro.Host = net.JoinHostPort(info.ServerName, "443")
				log = log.WithFields(map[string]any{
					"host":  ro.Host,
					"proto": ro.Proto,
				})

				if h.options.Bypass != nil &&
					h.options.Bypass.Contains(ctx, "udp", ro.Host, bypass.WithService(h.options.Service)) {
					log.Debug("bypass: ", ro.Host)
					return xbypass.ErrBypass
				}
			}
		}
	}

	dr, err := h.dialTarget(ctx, conn, ro, log, network, ro.Proto)
	if err != nil {
		return err
	}
	defer dr.cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), dr.target.Addr)

	if _, err := dr.cc.Write(clientDgram); err != nil {
		log.Debugf("outbound write: %v", err)
		return err
	}

	// Read the response.
	if err := dr.cc.SetReadDeadline(time.Now().Add(h.md.readTimeout)); err != nil {
		log.Debugf("set read deadline: %v", err)
		return err
	}
	n, err = dr.cc.Read(bufp)
	if err != nil {
		log.Debugf("outbound read: %v", err)
		return err
	}
	dr.cc.SetReadDeadline(time.Time{})

	respDgram := bufp[:n]

	if ro.Proto == sniffing.ProtoQUIC {
		if sh, shErr := quicdissector.SniffQUICServerHello(clientDgram, respDgram); shErr == nil {
			sniffing.PopulateQUICServerHello(sh, ro)
		}
	}

	if _, err := conn.Write(respDgram); err != nil {
		log.Debugf("conn write: %v", err)
		return err
	}

	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), dr.target.Addr)

	return nil
}
