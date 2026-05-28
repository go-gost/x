package local

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/forwarder"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("tcp", NewHandler)
	registry.HandlerRegistry().Register("udp", NewHandler)
	registry.HandlerRegistry().Register("forward", NewHandler)
}

type forwardHandler struct {
	hop      hop.Hop
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
	certPool tls_util.CertPool
}

// NewHandler creates a local forwarding handler with the given options.
// The handler registers for "tcp", "udp", and "forward" protocols.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &forwardHandler{
		options: options,
	}
}

func (h *forwardHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	if h.md.certificate != nil && h.md.privateKey != nil {
		h.certPool = tls_util.NewMemoryCertPool()
	}

	return
}

// Forward implements handler.Forwarder.
func (h *forwardHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

// Handle forwards the accepted connection to a node selected from the hop.
// When sniffing is enabled it inspects the initial bytes to detect HTTP or TLS
// traffic and delegates to the protocol-specific sniffer; otherwise it pipes the
// raw stream through the router.
func (h *forwardHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()
	ro := h.newRecorderObject(ctx, conn, start)
	network := ro.Network

	log := h.options.Logger.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})
	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	if h.options.Router == nil {
		err := errors.New("router not available")
		log.Error(err)
		return err
	}

	var proto string
	if network == "tcp" && h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, err = sniffing.Sniff(ctx, br)
		ro.Proto = proto
		if err != nil {
			log.Debugf("sniff: %v", err)
		}

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		conn = xnet.NewReadWriteConn(br, conn, conn)
		handled, sniffErr := h.handleSniffedProtocol(ctx, conn, ro, log, proto)
		if handled {
			return sniffErr
		}
	}

	return h.handleRawForwarding(ctx, conn, ro, log, network, proto)
}

// handleRawForwarding performs node selection, dials the target through the
// router, and pipes the raw connection. It is used when sniffing is disabled
// or the protocol was not HTTP/TLS.
func (h *forwardHandler) handleRawForwarding(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, network, proto string) error {
	target := &chain.Node{}
	if h.hop != nil {
		target = h.hop.Select(ctx,
			hop.ProtocolSelectOption(proto),
		)
	}
	if target == nil {
		err := errors.New("node not available")
		log.Error(err)
		return err
	}
	addr := target.Addr
	if opts := target.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			network = opts.Network
		default:
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":0"
			}
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
		return err
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}
	defer cc.Close()

	cc = proxyproto.WrapClientConn(
		h.md.proxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		cc)

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	// xnet.Transport(conn, cc)
	if err := xnet.Pipe(ctx, conn, cc, xnet.WithReadTimeout(h.md.readTimeout)); err != nil {
		log.Debugf("pipe: %v", err)
	}
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

// newRecorderObject creates a HandlerRecorderObject populated with connection
// metadata (service, addresses, network type, session ID, client address).
func (h *forwardHandler) newRecorderObject(ctx context.Context, conn net.Conn, start time.Time) *xrecorder.HandlerRecorderObject {
	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       start,
		SID:        xctx.SidFromContext(ctx).String(),
	}
	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}
	if _, ok := conn.(net.PacketConn); ok {
		ro.Network = "udp"
	}
	return ro
}

// sniffingDial creates a dial function for the sniffing branch that wraps
// Router.Dial with route recording and proxy protocol encapsulation.
func (h *forwardHandler) sniffingDial(ctx context.Context, network, address string, ro *xrecorder.HandlerRecorderObject) (net.Conn, error) {
	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "tcp", address)
	ro.Route = buf.String()
	return proxyproto.WrapClientConn(
		h.md.proxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		cc), err
}

// buildSniffer creates a forwarder.Sniffer configured from handler metadata.
func (h *forwardHandler) buildSniffer() *forwarder.Sniffer {
	return &forwarder.Sniffer{
		Websocket:           h.md.sniffingWebsocket,
		WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
		Recorder:            h.recorder.Recorder,
		RecorderOptions:     h.recorder.Options,
		Certificate:         h.md.certificate,
		PrivateKey:          h.md.privateKey,
		NegotiatedProtocol:  h.md.alpn,
		CertPool:            h.certPool,
		MitmBypass:          h.md.mitmBypass,
		ReadTimeout:         h.md.readTimeout,
	}
}

// handleSniffedProtocol dispatches a sniffed connection to the protocol-specific
// sniffer (HandleHTTP or HandleTLS). It returns (true, err) when the protocol was
// handled and (false, nil) when the caller should fall through to raw forwarding.
func (h *forwardHandler) handleSniffedProtocol(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, proto string) (handled bool, err error) {
	switch proto {
	case sniffing.ProtoHTTP, sniffing.ProtoTLS:
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return h.sniffingDial(ctx, network, address, ro)
		}
		sniffer := h.buildSniffer()
		if proto == sniffing.ProtoHTTP {
			return true, sniffer.HandleHTTP(ctx, conn,
				forwarder.WithService(h.options.Service),
				forwarder.WithDial(dial),
				forwarder.WithHop(h.hop),
				forwarder.WithBypass(h.options.Bypass),
				forwarder.WithHTTPKeepalive(h.md.httpKeepalive),
				forwarder.WithRecorderObject(ro),
				forwarder.WithLog(log),
			)
		}
		return true, sniffer.HandleTLS(ctx, conn,
			forwarder.WithService(h.options.Service),
			forwarder.WithDial(dial),
			forwarder.WithHop(h.hop),
			forwarder.WithBypass(h.options.Bypass),
			forwarder.WithRecorderObject(ro),
			forwarder.WithLog(log),
		)
	default:
		return false, nil
	}
}

func (h *forwardHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
