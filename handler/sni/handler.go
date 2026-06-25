// Package sni implements a TLS SNI-based forwarding handler for protocol-aware
// routing. It sniffs every inbound TCP connection, parses the TLS ClientHello
// (or HTTP request header) to extract the server name, and routes traffic
// through the proxy chain.
//
// # How it differs from the "tcp" / "forward" handler
//
// The SNI handler is purpose-built for TLS SNI routing — it always sniffs
// and only handles HTTP and TLS traffic:
//
//   - Non-HTTP/non-TLS connections are silently dropped (no raw forwarding
//     fallback). If you need raw TCP fallback, use the "tcp" or "forward"
//     handler instead.
//   - It does not implement [handler.Forwarder], so it has no hop-based node
//     selection, load balancing, or per-node authentication/rewrite settings.
//     All routing uses the SNI hostname as the destination address through
//     the configured chain.
//
// # Connection processing flow
//
// Each inbound net.Conn is processed by Handle:
//
//	Handle()
//	  ├─ newRecorderObject (session metadata: service, SID, addresses)
//	  ├─ checkRateLimit (connection rate limiter, if configured)
//	  ├─ Router nil check → errRouterNotAvailable
//	  ├─ sniffing.Sniff (peek buffer, detect protocol)
//	  │     └─ handleSniffedProtocol()
//	  │           ├─ sniffing.ProtoHTTP → SnifferBuilder.Build().HandleHTTP()
//	  │           ├─ sniffing.ProtoTLS  → SnifferBuilder.Build().HandleTLS()
//	  │           └─ default → silent drop
//	  └─ unrecognised protocol → silently returns nil
//
// # SnifferBuilder pattern
//
// The sniffer configuration (MITM certs, WebSocket recording, bypass rules)
// is immutable after Init. A [SnifferBuilder] is populated once during Init
// and reused via [SnifferBuilder.Build] to create per-connection
// [sniffing.Sniffer] instances.
package sni

import (
	"bufio"
	"context"
	"net"
	"time"

	"github.com/go-gost/core/handler"
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
	registry.HandlerRegistry().Register("sni", NewHandler)
}

// sniHandler is a protocol-aware forwarding handler that routes by TLS SNI
// or HTTP Host header. It always sniffs the initial bytes to determine the
// protocol and delegates to [sniffing.Sniffer] for HTTP/TLS handling.
type sniHandler struct {
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
	certPool tls_util.CertPool
	sniffer  *SnifferBuilder
}

// NewHandler creates an SNI handler with the given options.
// The handler registers for the "sni" protocol.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &sniHandler{
		options: options,
	}
}

// Init parses metadata and initialises the sniffer builder and TLS certificate
// pool. It implements [handler.Handler].
func (h *sniHandler) Init(md md.Metadata) (err error) {
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

	return nil
}

// Handle processes an inbound TCP connection. It always sniffs the initial
// bytes to detect HTTP or TLS, then delegates to the protocol-specific
// sniffer. Non-HTTP/non-TLS traffic is silently dropped.
//
// Handle implements [handler.Handler].
func (h *sniHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()
	ro := h.newRecorderObject(ctx, conn, start)

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
		err := errRouterNotAvailable
		log.Error(err)
		return err
	}

	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	br := bufio.NewReader(conn)
	proto, sniffErr := sniffing.Sniff(ctx, br)
	if sniffErr != nil {
		log.Debugf("sniff: %v", sniffErr)
	}
	ro.Proto = proto

	conn = xnet.NewReadWriteConn(br, conn, conn)
	handled, sniffErr := h.handleSniffedProtocol(ctx, conn, ro, log, proto)
	if handled {
		return sniffErr
	}

	log.Debugf("unrecognized traffic from %s", conn.RemoteAddr())
	return nil
}
