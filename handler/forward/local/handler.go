// Package local implements a low-level forwarding handler for raw TCP and UDP
// connections. It serves as the fallback handler for protocols that cannot be
// matched to a dedicated handler, and supports optional protocol sniffing to
// detect HTTP and TLS traffic for deep inspection (MITM, WebSocket recording).
//
// The handler is registered under the names "tcp", "udp", and "forward" via
// NewHandler in init().
//
// # Connection processing flow
//
// Each inbound net.Conn is processed by Handle, which wraps the connection
// with I/O stats, checks the rate limiter, and dispatches to one of two
// forwarding paths:
//
//	Handle()
//	  ├─ stats_wrapper.WrapConn (per-connection I/O counters)
//	  ├─ newRecorderObject (session metadata: service, SID, addresses)
//	  ├─ checkRateLimit (connection rate limiter, if configured)
//	  ├─ Router nil check → errRouterNotAvailable
//	  ├─ [sniffing enabled] sniffing.Sniff (peek buffer, detect protocol)
//	  │     └─ handleSniffedProtocol()
//	  │           ├─ sniffing.ProtoHTTP → SnifferBuilder.Build().HandleHTTP()
//	  │           ├─ sniffing.ProtoTLS  → SnifferBuilder.Build().HandleTLS()
//	  │           └─ default → fall through to raw forwarding
//	  └─ [sniffing disabled / unrecognised] handleRawForwarding()
//
// # Protocol sniffing dispatch (handleSniffedProtocol)
//
// When sniffing is enabled and the initial bytes match HTTP or TLS, the
// connection is delegated to the forwarder package for protocol-aware
// handling:
//
//   - HTTP: parses the request, applies MITM if configured, forwards to
//     the upstream, and records WebSocket frames when enabled.
//   - TLS: parses the ClientHello to extract the server name, applies
//     MITM or SNI-based routing through the hop, and records the TLS
//     handshake.
//
// SnifferBuilder is populated once during Init and reused via Build()
// to create per-connection forwarder.Sniffer instances.
//
// # Raw forwarding (handleRawForwarding)
//
// The default path for unrecognised traffic. It selects a target node
// from the hop, dials the upstream through the router, wraps the
// connection with proxy protocol (HAProxy) when enabled, and pipes
// data bidirectionally:
//
//  1. Node selection — getHop().Select() with optional protocol hint.
//  2. Router dial — Router.Dial() through the configured chain.
//  3. Proxy protocol — proxyproto.WrapClientConn() prepends HAProxy
//     header when metadata proxyProtocol is set.
//  4. Bidirectional pipe — xnet.Pipe(ctx, conn, cc) with read timeout.
//
// # Hop management
//
// The handler implements handler.Forwarder. Forward() is called during
// service startup (and on reload) to install or update the hop. The hop
// is protected by a mutex because Forward() runs on the loader goroutine
// while Handle() reads it from per-connection goroutines.
package local

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xnet "github.com/go-gost/x/internal/net"
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
	hopMu    sync.Mutex
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
	certPool tls_util.CertPool
	sniffer  *SnifferBuilder
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

	h.sniffer = &SnifferBuilder{
		Websocket:           h.md.sniffingWebsocket,
		WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
		Recorder:            h.recorder.Recorder,
		RecorderOptions:     h.recorder.Options,
		Certificate:         h.md.certificate,
		PrivateKey:          h.md.privateKey,
		ALPN:                h.md.alpn,
		CertPool:            h.certPool,
		MitmBypass:          h.md.mitmBypass,
		ReadTimeout:         h.md.readTimeout,
	}

	return
}

// Forward implements handler.Forwarder.
func (h *forwardHandler) Forward(hop hop.Hop) {
	h.hopMu.Lock()
	h.hop = hop
	h.hopMu.Unlock()
}

func (h *forwardHandler) getHop() hop.Hop {
	h.hopMu.Lock()
	defer h.hopMu.Unlock()
	return h.hop
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
		log.Error(errRouterNotAvailable)
		return errRouterNotAvailable
	}

	if h.md.stateless {
		return h.handleRawDatagram(ctx, conn, ro, log, network, "udp")
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
