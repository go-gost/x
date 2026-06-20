// Package masque implements a MASQUE (Multiplexed Application Substrate over
// QUIC Encryption) proxy handler for GOST. MASQUE is an IETF standard for
// tunneling IP traffic over HTTP/3, used by systems like Apple's iCloud
// Private Relay.
//
// This handler implements two proxy modes over HTTP/3 (QUIC):
//
//   - CONNECT-UDP (RFC 9298): Proxies UDP datagrams via HTTP/3 Datagram frames
//     (RFC 9297). The client sends an Extended CONNECT request with
//     :protocol="connect-udp" to the well-known path
//     "/.well-known/masque/udp/{host}/{port}/". UDP packets are then exchanged
//     as HTTP/3 datagrams with a context ID prefix per RFC 9297.
//
//   - CONNECT-TCP (RFC 9114): Tunnels TCP connections over HTTP/3 stream bodies.
//     The client sends a standard HTTP/3 CONNECT request with the target in the
//     :authority pseudo-header. Data is then relayed bidirectionally through the
//     HTTP/3 stream.
//
// # Request flow
//
// The HTTP/3 listener injects the http.ResponseWriter and http.Request into the
// context metadata. Handle() extracts them, validates the CONNECT method, and
// dispatches to handleConnectUDP or handleConnectTCP based on the :protocol
// pseudo-header (stored in r.Proto by quic-go).
//
// # Cross-cutting concerns
//
// The handler integrates with GOST's cross-cutting infrastructure: HTTP Basic
// proxy authentication, bypass rules, rate limiting, traffic limiting, Prometheus
// metrics, observer event reporting, and traffic recording.
//
// # Registration
//
// The handler is registered as "masque" in the handler registry via init().
// It must be paired with an HTTP/3 listener (registered as "h3") to function.
package masque

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
	masque_util "github.com/go-gost/x/internal/util/masque"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	"github.com/quic-go/quic-go/http3"
)

// init registers the MASQUE handler in the global handler registry under the
// name "masque". This enables the handler to be referenced by name in GOST
// configuration files and CLI flags (e.g., handler.type: masque).
func init() {
	registry.HandlerRegistry().Register("masque", NewHandler)
}

var (
	// ErrBadRequest indicates the request was malformed or invalid.
	ErrBadRequest         = errors.New("masque: bad request")
	// ErrMethodNotAllowed indicates the request method is not CONNECT.
	ErrMethodNotAllowed   = errors.New("masque: method not allowed")
	// ErrCapsuleRequired indicates the Capsule-Protocol header is missing or invalid.
	ErrCapsuleRequired    = errors.New("masque: capsule-protocol header required")
	// ErrDatagramNotSupport indicates that the QUIC connection does not support HTTP/3 datagrams.
	ErrDatagramNotSupport = errors.New("masque: datagrams not supported")
)

// masqueHandler implements handler.Handler for the MASQUE proxy protocol.
// It processes HTTP/3 CONNECT requests to tunnel UDP (RFC 9298) or TCP
// (RFC 9114) traffic through an HTTP/3 (QUIC) connection.
//
// The handler integrates with GOST's cross-cutting infrastructure:
//   - Authentication via HTTP Basic Proxy Authentication
//   - Bypass rules for selective target filtering
//   - Rate limiting and traffic limiting
//   - Observer event reporting for connection statistics
//   - Prometheus metrics collection
//   - Traffic recording for audit/logging
type masqueHandler struct {
	md       metadata                  // parsed configuration metadata
	options  handler.Options           // handler options (auth, bypass, router, etc.)
	stats    *stats_util.HandlerStats  // per-client connection statistics for observer
	limiter  traffic.TrafficLimiter    // cached traffic limiter wrapping the global limiter
	cancel   context.CancelFunc        // cancels the background observer goroutine
	recorder recorder.RecorderObject   // traffic recorder for handler-level events
}

// NewHandler creates a new MASQUE handler instance. It supports CONNECT-UDP
// (RFC 9298) for UDP proxying and standard HTTP/3 CONNECT (RFC 9114) for TCP
// tunneling. The returned handler must be initialized via Init() before use.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &masqueHandler{
		options: options,
	}
}

// Init initializes the MASQUE handler with the provided metadata. It:
//   - Parses configuration from metadata (buffer sizes, timeouts, etc.)
//   - Starts a background observer goroutine if an Observer is configured
//   - Creates a cached traffic limiter wrapping the global limiter
//   - Selects the handler-level recorder from the configured recorders
func (h *masqueHandler) Init(md md.Metadata) error {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	if h.options.Observer != nil {
		h.stats = stats_util.NewHandlerStats(h.options.Service, h.md.observerResetTraffic)
		go h.observeStats(ctx)
	}

	if h.options.Limiter != nil {
		h.limiter = cache_limiter.NewCachedTrafficLimiter(h.options.Limiter,
			cache_limiter.RefreshIntervalOption(h.md.limiterRefreshInterval),
			cache_limiter.CleanupIntervalOption(h.md.limiterCleanupInterval),
			cache_limiter.ScopeOption(limiter.ScopeClient),
		)
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return nil
}

// Handle processes an inbound MASQUE connection. It extracts the HTTP/3 request
// and response writer from the context metadata (injected by the HTTP/3 listener),
// validates the CONNECT method, and dispatches to the appropriate handler based on
// the :protocol pseudo-header:
//   - "connect-udp" → handleConnectUDP (RFC 9298, UDP over HTTP/3 datagrams)
//   - "HTTP/3.0" or "" → handleConnectTCP (RFC 9114, TCP over HTTP/3 stream)
//
// The connection's entire lifecycle — rate limiting, stats recording, traffic
// metrics, and cleanup — is managed within this method and its deferred cleanup.
func (h *masqueHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "",
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Proto:      "masque",
		Time:       start,
		SID:        xctx.SidFromContext(ctx).String(),
	}

	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}

	log := h.options.Logger.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})
	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	// pStats tracks per-connection I/O byte counts for recording and logging.
	pStats := &xstats.Stats{}

	// Deferred cleanup: record traffic stats, log session end, and report errors.
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if h.recorder.Recorder != nil {
			if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
				log.Errorf("record: %v", err)
			}
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

	// The HTTP/3 listener injects the http.ResponseWriter and http.Request
	// into the context metadata so the handler can access the HTTP/3
	// request/response layer. Without this metadata, the connection did not
	// originate from an HTTP/3 listener and MASQUE cannot operate.
	ctxMd := ictx.MetadataFromContext(ctx)
	if ctxMd == nil {
		err := errors.New("masque: wrong connection type, requires HTTP/3")
		log.Error(err)
		return err
	}

	// w is the HTTP/3 response writer; r is the HTTP/3 request.
	// These are set by the HTTP/3 listener when accepting the QUIC stream.
	w, _ := ctxMd.Get("w").(http.ResponseWriter)
	r, _ := ctxMd.Get("r").(*http.Request)

	if w == nil {
		return ErrBadRequest
	}
	if r == nil {
		w.WriteHeader(http.StatusBadRequest)
		return ErrBadRequest
	}

	// Validate CONNECT method
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		log.Error(ErrMethodNotAllowed)
		return ErrMethodNotAllowed
	}

	// Dispatch based on :protocol pseudo-header
	// In quic-go, the :protocol pseudo-header is stored in r.Proto
	switch r.Proto {
	case "connect-udp":
		// Extended CONNECT for UDP (RFC 9298)
		ro.Network = "udp"
		return h.handleConnectUDP(ctx, w, r, conn.LocalAddr(), ro, log, pStats)
	case "HTTP/3.0", "":
		// Standard CONNECT for TCP (RFC 9114)
		// r.Proto is "HTTP/3.0" for standard HTTP/3 CONNECT (no :protocol header)
		ro.Network = "tcp"
		return h.handleConnectTCP(ctx, w, r, conn.LocalAddr(), ro, log, pStats)
	default:
		w.WriteHeader(http.StatusBadRequest)
		log.Errorf("masque: unsupported protocol: %s", r.Proto)
		return ErrBadRequest
	}
}

// Close shuts down the MASQUE handler by cancelling the background observer
// goroutine. It is called when the owning service is stopped.
func (h *masqueHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

// handleConnectUDP implements the CONNECT-UDP method (RFC 9298). It proxies UDP
// datagrams between the MASQUE client and the target host using HTTP/3 datagrams
// (RFC 9297) as the transport.
//
// Request flow:
//  1. Authenticate the client via HTTP Basic Proxy Authentication
//  2. Parse the target host:port from the URI template path
//     "/.well-known/masque/udp/{host}/{port}/"
//  3. Check bypass rules for the target address
//  4. Validate the Capsule-Protocol header (required by RFC 9298)
//  5. Obtain the HTTP/3 stream and respond with 200 OK + Capsule-Protocol header
//  6. Create a DatagramConn wrapping the HTTP/3 stream's datagram interface
//  7. Dial the target (via Router chain or direct UDP socket)
//  8. Run a bidirectional UDP relay between client and target
//
// Data path:
//
//	Client ↔ HTTP/3 Datagram ↔ DatagramConn ↔ [stats/limiter wrappers] ↔ UDP Relay ↔ Target
func (h *masqueHandler) handleConnectUDP(ctx context.Context, w http.ResponseWriter, r *http.Request, laddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger, pStats *xstats.Stats) error {
	if u, _, _ := h.basicProxyAuth(r.Header.Get("Proxy-Authorization")); u != "" {
		log = log.WithFields(map[string]any{"user": u})
		ro.ClientID = u
	}

	// Authenticate
	clientID, ok := h.authenticate(ctx, w, r, log)
	if !ok {
		return errors.New("authentication failed")
	}

	if clientID != "" {
		log = log.WithFields(map[string]any{"clientID": clientID})
		ro.ClientID = clientID
	}
	ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))

	// Parse target from path
	host, port, err := masque_util.ParseMasquePath(r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Error("masque: invalid path: ", err)
		return err
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	ro.Host = targetAddr
	log = log.WithFields(map[string]any{
		"target": targetAddr,
	})
	log.Debug("connect-udp request to ", targetAddr)

	// Check bypass
	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, "udp", targetAddr, bypass.WithService(h.options.Service)) {
		w.WriteHeader(http.StatusForbidden)
		log.Debug("bypass: ", targetAddr)
		return xbypass.ErrBypass
	}

	// Validate capsule-protocol header (required for CONNECT-UDP per RFC 9298)
	if r.Header.Get("Capsule-Protocol") != "?1" {
		w.WriteHeader(http.StatusBadRequest)
		log.Error(ErrCapsuleRequired)
		return ErrCapsuleRequired
	}

	// Resolve target address
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Error("masque: failed to resolve target address: ", err)
		return err
	}

	// Get HTTP/3 stream for datagrams
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error(ErrDatagramNotSupport)
		return ErrDatagramNotSupport
	}

	// Get the underlying HTTP/3 stream
	stream := streamer.HTTPStream()

	// Get target connection - either through router/chain or direct
	var targetPC net.PacketConn

	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: targetAddr})
	}

	var buf bytes.Buffer

	if h.options.Router != nil {
		// Use router to dial through chain (for forwarding through upstream proxy)
		c, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "udp", targetAddr)
		ro.Route = buf.String()
		if err != nil {
			log.Error("masque: failed to dial through router: ", err)
			return err
		}
		defer c.Close()

		ro.SrcAddr = c.LocalAddr().String()

		// The connection from router should be a PacketConn (e.g., from masque connector)
		if pc, ok := c.(net.PacketConn); ok {
			targetPC = pc
			log.Debugf("relaying UDP to %s via chain", targetAddr)
		} else {
			// Wrap as PacketConn if it's a regular Conn
			targetPC = &connPacketConn{Conn: c, raddr: raddr}
			log.Debugf("relaying UDP to %s via chain (wrapped)", targetAddr)
		}
	} else {
		// Direct connection - create local UDP socket
		directConn, err := net.ListenPacket("udp", "")
		if err != nil {
			log.Error("masque: failed to create UDP socket: ", err)
			return err
		}
		defer directConn.Close()

		ro.SrcAddr = directConn.LocalAddr().String()

		// Wrap with fixed target address
		targetPC = &fixedTargetPacketConn{
			PacketConn: directConn,
			target:     raddr,
		}
		log.Debugf("relaying UDP to %s directly via %s", raddr, directConn.LocalAddr())
	}

	// Wrap target with metrics
	targetPC = metrics.WrapPacketConn(h.options.Service, targetPC)

	// Send success response with capsule-protocol header
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)

	// Flush the response headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Create datagram connection wrapping the HTTP/3 stream (client side)
	datagramConn := masque_util.NewDatagramConn(stream, laddr, raddr)
	defer datagramConn.Close()

	// Wrap with recorder stats and traffic limiter
	var clientPC net.PacketConn = datagramConn
	clientPC = stats_wrapper.WrapPacketConn(clientPC, pStats)
	clientPC = traffic_wrapper.WrapPacketConn(
		clientPC,
		h.limiter,
		clientID,
		limiter.ServiceOption(h.options.Service),
		limiter.ScopeOption(limiter.ScopeClient),
		limiter.NetworkOption("udp"),
		limiter.AddrOption(targetAddr),
		limiter.ClientOption(clientID),
		limiter.SrcOption(ro.RemoteAddr),
	)

	// Track per-client connection stats
	if h.options.Observer != nil {
		pstats := h.stats.Stats(clientID)
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
		clientPC = stats_wrapper.WrapPacketConn(clientPC, pstats)
	}

	// Relay UDP packets between client and target
	relay := udp.NewRelay(clientPC, targetPC).
		WithService(h.options.Service).
		WithLogger(log).
		WithBufferSize(h.md.bufferSize)

	return relay.Run(ctx)
}

// handleConnectTCP implements standard HTTP/3 CONNECT (RFC 9114) for TCP
// tunneling. Data is relayed bidirectionally through the HTTP/3 stream body
// (not via datagrams), providing a reliable, ordered byte stream.
//
// Request flow:
//  1. Authenticate the client via HTTP Basic Proxy Authentication
//  2. Extract the target address from the :authority pseudo-header (r.Host),
//     defaulting to port 443 if no port is specified
//  3. Check bypass rules for the target address
//  4. Dial the target (via Router chain or direct TCP connection)
//  5. Obtain the HTTP/3 stream and respond with 200 OK
//  6. Create a StreamConn wrapping the HTTP/3 stream body
//  7. Run bidirectional data relay between client and target
//
// Data path:
//
//	Client ↔ HTTP/3 Stream Body ↔ StreamConn ↔ [stats/limiter wrappers] ↔ xnet.Pipe ↔ Target
func (h *masqueHandler) handleConnectTCP(ctx context.Context, w http.ResponseWriter, r *http.Request, laddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger, pStats *xstats.Stats) error {
	// Extract user for logging
	if u, _, _ := h.basicProxyAuth(r.Header.Get("Proxy-Authorization")); u != "" {
		log = log.WithFields(map[string]any{"user": u})
		ro.ClientID = u
	}

	// Authenticate
	clientID, ok := h.authenticate(ctx, w, r, log)
	if !ok {
		return errors.New("authentication failed")
	}

	if clientID != "" {
		log = log.WithFields(map[string]any{"clientID": clientID})
		ro.ClientID = clientID
	}
	ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))

	// Target address comes from :authority (r.Host) for standard CONNECT
	targetAddr := r.Host
	if targetAddr == "" {
		w.WriteHeader(http.StatusBadRequest)
		log.Error("masque: missing target address in :authority")
		return ErrBadRequest
	}

	// Ensure port is present
	if _, port, _ := net.SplitHostPort(targetAddr); port == "" {
		targetAddr = net.JoinHostPort(strings.Trim(targetAddr, "[]"), "443")
	}

	ro.Host = targetAddr
	log = log.WithFields(map[string]any{
		"target": targetAddr,
	})
	log.Debug("connect-tcp request to ", targetAddr)

	// Check bypass
	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, "tcp", targetAddr, bypass.WithService(h.options.Service)) {
		w.WriteHeader(http.StatusForbidden)
		log.Debug("bypass: ", targetAddr)
		return xbypass.ErrBypass
	}

	// Resolve target address for StreamConn
	raddr, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		log.Error("masque: failed to resolve target address: ", err)
		return err
	}

	// Dial target connection
	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: targetAddr})
	}

	var cc net.Conn
	var buf bytes.Buffer

	if h.options.Router != nil {
		cc, err = h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "tcp", targetAddr)
	} else {
		cc, err = net.Dial("tcp", targetAddr)
	}
	ro.Route = buf.String()

	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		log.Error("masque: failed to dial target: ", err)
		return err
	}
	defer cc.Close()

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	// Get HTTP/3 stream
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error("masque: failed to get HTTP/3 streamer")
		return errors.New("masque: HTTP/3 streamer not available")
	}

	// Get the underlying HTTP/3 stream
	stream := streamer.HTTPStream()

	// Send 200 OK response
	w.WriteHeader(http.StatusOK)

	// Flush the response headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Create stream connection wrapping the HTTP/3 stream
	streamConn := masque_util.NewStreamConn(stream, laddr, raddr)
	defer streamConn.Close()

	// Wrap with recorder stats and traffic limiter
	var clientConn net.Conn = streamConn
	clientConn = stats_wrapper.WrapConn(clientConn, pStats)
	clientConn = traffic_wrapper.WrapConn(
		clientConn,
		h.limiter,
		clientID,
		limiter.ServiceOption(h.options.Service),
		limiter.ScopeOption(limiter.ScopeClient),
		limiter.NetworkOption("tcp"),
		limiter.AddrOption(targetAddr),
		limiter.ClientOption(clientID),
		limiter.SrcOption(ro.RemoteAddr),
	)

	// Track per-client connection stats
	if h.options.Observer != nil {
		pstats := h.stats.Stats(clientID)
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
		clientConn = stats_wrapper.WrapConn(clientConn, pstats)
	}

	// Wrap target with metrics
	cc = metrics.WrapConn(h.options.Service, cc)

	log.Infof("%s <-> %s", ro.RemoteAddr, targetAddr)

	// Bidirectional relay
	xnet.Pipe(ctx, clientConn, cc, xnet.WithReadTimeout(h.md.idleTimeout))

	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, targetAddr)

	return nil
}

// fixedTargetPacketConn wraps a net.PacketConn and pins all reads and writes
// to a single target address. This is used for direct UDP forwarding where
// the MASQUE target address is fixed for the lifetime of the connection.
// ReadFrom returns the fixed target as the source address (instead of the
// actual source), so the UDP relay always sees a consistent peer.
type fixedTargetPacketConn struct {
	net.PacketConn
	target net.Addr
}

// ReadFrom reads a packet from the underlying PacketConn but returns the
// fixed target address as the source, ignoring the actual source address.
func (c *fixedTargetPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, _, err = c.PacketConn.ReadFrom(b)
	return n, c.target, err
}

// WriteTo writes a packet to the fixed target address, ignoring the addr parameter.
func (c *fixedTargetPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.PacketConn.WriteTo(b, c.target)
}

// connPacketConn adapts a stream-based net.Conn to the net.PacketConn interface
// for use with the UDP relay. This is needed when the Router returns a
// connection from an upstream MASQUE connector (which uses HTTP/3 stream body
// framing rather than datagrams). Each Read/Write maps to a single
// ReadFrom/WriteTo with the fixed remote address.
type connPacketConn struct {
	net.Conn
	raddr net.Addr
}

// ReadFrom reads data from the stream connection and reports the fixed remote address.
func (c *connPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(b)
	return n, c.raddr, err
}

// WriteTo writes data to the stream connection, ignoring the addr parameter.
func (c *connPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Conn.Write(b)
}

// checkRateLimit checks whether the connection from the given address is
// allowed by the rate limiter. Returns true if the connection is allowed
// (including when no rate limiter is configured), false if the limit is exceeded.
// The rate limit is applied per client IP (host portion of the address).
func (h *masqueHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

// observeStats is a background goroutine that periodically collects per-client
// connection statistics from the HandlerStats and reports them to the Observer.
// It runs until the context is cancelled (when the handler is closed).
//
// If the Observer fails to accept events, they are buffered and retried on the
// next tick to avoid data loss during transient failures.
func (h *masqueHandler) observeStats(ctx context.Context) {
	if h.options.Observer == nil {
		return
	}

	var events []observer.Event

	ticker := time.NewTicker(h.md.observerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Try to flush any buffered events from a previous failed attempt.
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err != nil {
					continue
				}
			}

			// Collect and send fresh events.
			if evs := h.stats.Events(); len(evs) > 0 {
				if err := h.options.Observer.Observe(ctx, evs); err != nil {
					events = evs
					continue
				}
			}
			events = nil

		case <-ctx.Done():
			return
		}
	}
}

// basicProxyAuth parses an HTTP Basic Proxy-Authorization header value.
// It decodes the Base64-encoded "username:password" credentials.
// Returns the username, password, and true on success, or empty strings
// and false if the header is missing, malformed, or not Basic auth.
func (h *masqueHandler) basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}

// authenticate validates the client's proxy credentials against the configured
// Authenticator. If no Authenticator is configured, all requests are allowed.
// On authentication failure, it sends a 407 Proxy Authentication Required response
// with a Proxy-Authenticate challenge header and returns ("", false).
// On success, it returns the authenticated client ID and true.
func (h *masqueHandler) authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, log logger.Logger) (id string, ok bool) {
	u, p, _ := h.basicProxyAuth(r.Header.Get("Proxy-Authorization"))
	if h.options.Auther == nil {
		return "", true
	}
	if id, ok = h.options.Auther.Authenticate(ctx, u, p, auth.WithService(h.options.Service)); ok {
		return
	}

	realm := defaultRealm
	if h.md.authBasicRealm != "" {
		realm = h.md.authBasicRealm
	}
	w.Header().Set("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
	w.WriteHeader(http.StatusProxyAuthRequired)
	log.Debug("proxy authentication required")
	return
}
