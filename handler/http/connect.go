package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	stats "github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleConnect handles HTTP CONNECT tunnel requests. It dials the target
// address through the proxy chain router, sends a "200 Connection established"
// response to the client, and then relays raw bytes bidirectionally between
// client and upstream.
//
// When sniffing is enabled, the initial bytes from the client are inspected.
// If they match HTTP or TLS, the connection is handed off to the sniffer for
// protocol-aware forwarding (HTTP request routing, TLS MITM decryption).
// If the sniffed protocol is unknown, or sniffing is disabled, raw pipe
// forwarding is used.
func (h *httpHandler) handleConnect(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, addr string, resp *http.Response) error {
	ctx = ictx.ContextWithRecorderObject(ctx, ro)
	ctx = ictx.ContextWithLogger(ctx, log)
	cc, err := h.dial(ctx, "tcp", addr)
	if err != nil {
		resp.StatusCode = http.StatusServiceUnavailable

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		if err := resp.Write(conn); err != nil {
			log.Error("write error response: ", err)
		}
		return err
	}
	// snifferHandled tracks whether the upstream connection has been taken
	// over by the sniffer. If the sniffer doesn't claim it, we close cc.
	snifferHandled := false
	defer func() {
		if !snifferHandled {
			cc.Close()
		}
	}()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	b := buildConnectResponse(h.md.proxyAgent)
	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Trace(string(b))
	}
	if _, err = conn.Write(b); err != nil {
		log.Error(err)
		return err
	}

	if h.md.sniffing {
		snifferHandled, err = h.sniffAndHandle(ctx, conn, cc, ro, log)
		if snifferHandled {
			return err
		}
	}

	start := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
	xnet.Pipe(ctx, conn, cc, xnet.WithReadTimeout(h.md.idleTimeout))
	log.WithFields(map[string]any{
		"duration": time.Since(start),
	}).Infof("%s >-< %s", conn.RemoteAddr(), addr)

	return nil
}

// sniffAndHandle peeks at the initial bytes of the client connection to
// determine the protocol. If HTTP or TLS is detected, the connection is
// handed off to the appropriate sniffer handler for protocol-aware forwarding.
// The dial and dialTLS closures return the already-established upstream
// connection so that the sniffer uses the same tunnel.
//
// Returns (true, err) when the sniffer took over the connection. Returns
// (false, nil) when the protocol is unrecognised and the caller should
// fall back to raw pipe forwarding.
func (h *httpHandler) sniffAndHandle(ctx context.Context, conn net.Conn, cc net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (handled bool, err error) {
	if h.md.sniffingTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
	}

	br := bufio.NewReader(conn)
	proto, _ := sniffing.Sniff(ctx, br)
	ro.Proto = proto

	if h.md.sniffingTimeout > 0 {
		conn.SetReadDeadline(time.Time{})
	}

	// Both dial closures return the existing upstream connection so the
	// sniffer uses the same tunnel rather than dialling a new one.
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return cc, nil
	}
	dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
		return cc, nil
	}
	sniffer := h.sniffer.Build()

	conn = xnet.NewReadWriteConn(br, conn, conn)
	switch proto {
	case sniffing.ProtoHTTP:
		return true, sniffer.HandleHTTP(ctx, "tcp", conn,
			sniffing.WithService(h.options.Service),
			sniffing.WithDial(dial),
			sniffing.WithDialTLS(dialTLS),
			sniffing.WithBypass(h.options.Bypass),
			sniffing.WithRecorderObject(ro),
			sniffing.WithLog(log),
		)
	case sniffing.ProtoTLS:
		return true, sniffer.HandleTLS(ctx, "tcp", conn,
			sniffing.WithService(h.options.Service),
			sniffing.WithDial(dial),
			sniffing.WithDialTLS(dialTLS),
			sniffing.WithBypass(h.options.Bypass),
			sniffing.WithRecorderObject(ro),
			sniffing.WithLog(log),
		)
	}

	return false, nil
}

// dial establishes an upstream connection through the proxy chain router.
// It attaches the recorder object and logger from the context so that the
// router can annotate the route path and source/destination addresses.
//
// When h.md.hash is "host", the target address is used as the hash source
// for consistent hop selection across the chain.
func (h *httpHandler) dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: addr})
	}

	if log := ictx.LoggerFromContext(ctx); log != nil {
		log.Debugf("dial: new connection to host %s", addr)
	}

	if h.options.Router == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: nil, Err: errors.New("nil router")}
	}

	var buf bytes.Buffer
	conn, err = h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, addr)
	if ro := ictx.RecorderObjectFromContext(ctx); ro != nil {
		ro.Route = buf.String()

		if conn != nil {
			ro.SrcAddr = conn.LocalAddr().String()
			ro.DstAddr = conn.RemoteAddr().String()
		}
	}

	return
}

// setupTrafficLimiter wraps the connection with per-client traffic shaping
// and optional stats tracking. When an Observer is configured, per-client
// stats counters (total connections, current connections) are updated.
//
// The returned net.Conn reads and writes through the limiter and stats
// wrappers while still satisfying the net.Conn interface.
//
// The cleanup function (non-nil when an Observer is configured) must be
// deferred by the caller to decrement KindCurrentConns when the connection
// handling completes. It captures the per-client stats object so the
// deferred call fires in the caller's scope, not when setupTrafficLimiter
// returns.
func (h *httpHandler) setupTrafficLimiter(conn net.Conn, clientID, network, addr string) (net.Conn, func()) {
	rw := traffic_wrapper.WrapReadWriter(
		h.limiter,
		conn,
		clientID,
		limiter.ScopeOption(limiter.ScopeClient),
		limiter.ServiceOption(h.options.Service),
		limiter.NetworkOption(network),
		limiter.AddrOption(addr),
		limiter.ClientOption(clientID),
		limiter.SrcOption(conn.RemoteAddr().String()),
	)
	var cleanup func()
	if h.options.Observer != nil {
		pstats := h.stats.Stats(clientID)
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		cleanup = func() { pstats.Add(stats.KindCurrentConns, -1) }
		rw = stats_wrapper.WrapReadWriter(rw, pstats)
	}

	return xnet.NewReadWriteConn(rw, rw, conn), cleanup
}

// SnifferBuilder holds all configuration needed to construct a sniffing.Sniffer.
// It is populated once during Init and reused for each sniffed connection.
type SnifferBuilder struct {
	Websocket           bool
	WebsocketSampleRate float64
	Recorder            recorder.Recorder
	RecorderOptions     *recorder.Options
	Certificate         *x509.Certificate
	PrivateKey          crypto.PrivateKey
	ALPN                string
	CertPool            tls_util.CertPool
	MitmBypass          bypass.Bypass
	// ReadTimeout is the timeout for reading upstream HTTP response headers
	// and TLS ServerHello during sniffing. Passed through to sniffing.Sniffer.
	// See sniffing.Sniffer.ReadTimeout for details.
	ReadTimeout time.Duration
}

// Build creates a new sniffing.Sniffer from the builder's configuration.
func (b *SnifferBuilder) Build() *sniffing.Sniffer {
	return &sniffing.Sniffer{
		Websocket:           b.Websocket,
		WebsocketSampleRate: b.WebsocketSampleRate,
		Recorder:            b.Recorder,
		RecorderOptions:     b.RecorderOptions,
		Certificate:         b.Certificate,
		PrivateKey:          b.PrivateKey,
		NegotiatedProtocol:  b.ALPN,
		CertPool:            b.CertPool,
		MitmBypass:          b.MitmBypass,
		ReadTimeout:         b.ReadTimeout,
	}
}
