// Package http implements an HTTP/HTTPS proxy handler. It supports both
// forward proxy (GET/POST/CONNECT) and tunnel modes with optional TLS
// sniffing, MITM decryption, WebSocket frame recording, probe resistance,
// and UDP relay.
//
// The handler is registered under the name "http" and created via
// NewHandler in init().
//
// # Request processing flow
//
// Each inbound net.Conn is handled by Handle, which reads exactly one
// HTTP request and delegates to handleRequest for routing. The flow
// through the handler proceeds as follows:
//
//	Handle()
//	  ├─ stats.WrapConn (per-connection I/O counters)
//	  ├─ checkRateLimit (connection rate limiter, if configured)
//	  ├─ http.ReadRequest
//	  ├─ xhttp.GetClientIP (extract client IP from headers)
//	  └─ handleRequest()
//
// # Request dispatch (handleRequest)
//
// handleRequest is the central dispatcher. It normalises the request
// and routes to one of three code paths:
//
//  1. URL scheme inference — if the URL is not absolute (plain HTTP
//     proxy request), the Host header is validated with govalidator.
//     A valid DNS name or IP address implies the scheme is "http".
//
//  2. Network detection — reads the X-Gost-Protocol header. If the
//     value is "udp" the request is treated as a UDP relay; otherwise
//     it defaults to "tcp".
//
//  3. GOST v2 compatibility — decodes Gost-Target and X-Gost-Target
//     headers (base64+CRC32 encoding) to recover the actual target host
//     from older GOST clients.
//
//  4. Host normalisation — appends ":80" if no port is present.
//
//  5. Authentication — see "Authentication and probe resistance" below.
//
//  6. Bypass check — if a bypass matcher is configured and the target
//     address matches, a 403 Forbidden is returned.
//
//  7. Routing:
//     • X-Gost-Protocol: udp → handleUDP
//     • setupTrafficLimiter wraps the conn (per-client shaping + observer stats)
//     • Method != CONNECT → handleProxy (forward proxy)
//     • Method == CONNECT → handleConnect (tunnel)
//
// # Forward proxy path (handleProxy → proxyRoundTrip)
//
// handleProxy wraps the connection with per-request stats, performs the
// first round-trip via proxyRoundTrip, then enters a keep-alive loop
// reading and proxying subsequent requests on the same connection until
// the client or upstream closes.
//
// proxyRoundTrip performs a single HTTP round-trip:
//   - Clones the recorder object for per-request isolation.
//   - Normalises the host (adds default port if missing).
//   - Handles HTTP/1.0 compatibility (Connection: keep-alive / close).
//   - Strips proxy-specific headers: Proxy-Authorization, Proxy-Connection,
//     Gost-Target, X-Gost-Target.
//   - Checks bypass rules (403 Forbidden on match).
//   - Optionally intercepts the request body for recording (tee reader).
//   - Sends the request through the upstream http.Transport (which dials
//     through the proxy chain router via h.dial).
//   - Optionally intercepts the response body for recording.
//   - Handles 101 Switching Protocols (see "WebSocket upgrade" below).
//   - Writes the response to the client.
//
// # CONNECT tunnel path (handleConnect → sniffAndHandle)
//
// handleConnect implements the HTTP CONNECT tunnel:
//  1. Dials the target address through the proxy chain router (h.dial).
//  2. On dial failure, writes a 503 Service Unavailable to the client.
//  3. Writes "200 Connection established" to the client.
//  4. If sniffing is enabled, calls sniffAndHandle to inspect the
//     initial bytes from the client.
//  5. If sniffAndHandle does not claim the connection, falls back to
//     raw bidirectional pipe forwarding (xnet.Pipe).
//
// sniffAndHandle peeks at the client's initial bytes:
//   - Sets a read deadline (sniffing.timeout) to bound the peek.
//   - Calls sniffing.Sniff to classify the protocol.
//   - For HTTP traffic: delegates to sniffer.HandleHTTP (HTTP request
//     routing through the tunnel).
//   - For TLS traffic: delegates to sniffer.HandleTLS (MITM decryption
//     if certificates are configured, or blind forwarding).
//   - For unrecognised protocols: returns (false, nil), and the caller
//     falls back to raw pipe forwarding.
//   - Both sniff handlers receive dial closures that return the
//     already-established upstream connection, so the sniffer uses the
//     same tunnel rather than opening a new one.
//
// # WebSocket upgrade (handleUpgradeResponse)
//
// When proxyRoundTrip receives a 101 Switching Protocols response:
//  1. Validates that the request and response upgrade types match.
//  2. Extracts the backend connection from the response body
//     (the HTTP transport upgrades the connection on 101).
//  3. Writes the 101 response to the client.
//  4. If the upgrade is "websocket" and sniffing.websocket is enabled,
//     starts frame-level recording via sniffingWebsocketFrame.
//  5. Otherwise, falls back to raw bidirectional pipe forwarding.
//
// sniffingWebsocketFrame runs two goroutines (one per direction) that
// read WebSocket frames, record metadata and optionally the payload
// (subject to a rate limiter with sniffing.websocket.sampleRate), and
// forward the frames to the peer. The first direction to encounter an
// error terminates the relay.
//
// # Authentication and probe resistance (authenticate)
//
// authenticate extracts credentials from the Proxy-Authorization header
// (HTTP Basic auth) and validates them against the configured Auther.
//
// When no Auther is configured, all requests are anonymous (id="", ok=true).
//
// When authentication fails and probeResistance is configured, the handler
// returns a decoy response instead of the normal 407 Proxy-Auth-Required,
// making the port appear to run a different service. Four strategies are
// supported:
//
//	code:  respond with a custom HTTP status code  (e.g. "code:404")
//	web:   fetch a URL and replay its response       (e.g. "web:example.com")
//	host:  forward the raw request to a decoy host   (e.g. "host:1.2.3.4:80")
//	file:  serve a local file with Content-Type: text/html
//
// The knock feature (pr.Knock) restricts probe resistance to clients
// that don't know a secret hostname. When pr.Knock is set and the request
// hostname matches, probe resistance is bypassed and the normal 407 is
// returned — revealing the proxy only to clients that know the knock
// address.
//
// # UDP relay (handleUDP)
//
// When X-Gost-Protocol is "udp":
//   - If enableUDP is false, a 403 Forbidden is returned.
//   - Otherwise a 200 OK is written, a UDP association is dialled through
//     the proxy chain router, and the HTTP connection is wrapped as a
//     SOCKS5 UDP tunnel. Client data is read as SOCKS5-encapsulated UDP
//     datagrams and relayed through the chain.
//
// # Upstream dialing (dial)
//
// dial establishes upstream connections through the proxy chain router.
// It attaches the recorder object and logger from the context and, when
// h.md.hash is "host", sets the target address as the hash source for
// consistent hop selection. The route taken is written to the recorder
// object via the context buffer.
//
// # Initialisation (Init)
//
// Init parses metadata, creates a cached traffic limiter, starts the
// background stats observer goroutine, picks the first service-handler
// recorder, initialises the MITM certificate pool (if mitm.certFile and
// mitm.keyFile are both provided), and builds the upstream http.Transport.
// The transport dials through the proxy chain via h.dial.
//
// # Observability
//
// Per-connection stats are tracked via stats_wrapper.WrapConn in Handle.
// Per-client stats (KindTotalConns, KindCurrentConns) are tracked in
// setupTrafficLimiter and published to the configured Observer on a
// periodic ticker (observerPeriod, default 5s, min 1s). The observeStats
// goroutine retries previously failed events before sending new ones.
//
// # Key configuration (metadata)
//
//	readTimeout:      upstream response header timeout (default 15s, negative disables)
//	idleTimeout:      pipe forwarding idle timeout (0 = disabled)
//	keepalive:        enable HTTP keep-alive on the upstream transport
//	compression:      enable HTTP compression on the upstream transport
//	probeResist:      decoy response on auth failure (format "type:value")
//	knock:            secret hostname that bypasses probe resistance
//	udp:              enable UDP relay
//	sniffing:         enable protocol sniffing on CONNECT tunnels
//	sniffing.timeout: read deadline for the initial sniff peek
//	sniffing.websocket: enable WebSocket frame recording
//	sniffing.websocket.sampleRate: max frames recorded per second
//	mitm.certFile / mitm.keyFile: CA certificate pair for TLS decryption
//	mitm.bypass:      named bypass matcher to skip MITM decryption
//	hash:             hop selection strategy ("host" for consistent hashing)
//	observerPeriod:   stats reporting interval (default 5s, min 1s)
//	proxyAgent:       Proxy-Agent header value (default "gost/3.0")
package http

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	stats "github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	stats_util "github.com/go-gost/x/internal/util/stats"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("http", NewHandler)
}

// httpHandler is the HTTP/HTTPS proxy handler implementation. It holds the
// parsed metadata, handler options, and runtime state such as the traffic
// limiter, recorder, certificate pool, and the upstream HTTP transport.
type httpHandler struct {
	md        metadata                // parsed configuration
	options   handler.Options         // handler options from the service config
	auth      *Authenticator          // auth + probe resistance (constructed in Init)
	sniffer   *SnifferBuilder         // builds sniffing.Sniffer per connection
	stats     *stats_util.HandlerStats // per-client stats, created when Observer is set
	limiter   traffic.TrafficLimiter  // per-client traffic shaper (cached)
	cancel    context.CancelFunc      // cancels the observeStats goroutine
	recorder  recorder.RecorderObject // first matching service-handler recorder
	certPool  tls_util.CertPool       // in-memory cert pool for MITM TLS termination
	transport http.RoundTripper       // upstream HTTP transport (injectable for tests)
}

// NewHandler creates a new HTTP handler and applies the given options.
// It is called by the registry when a service references the "http" handler.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &httpHandler{
		options: options,
	}
}

// Init parses metadata, creates the traffic limiter and stats tracker,
// picks the first matching recorder, initialises the MITM cert pool if
// a certificate is configured, and builds the upstream http.Transport.
func (h *httpHandler) Init(md md.Metadata) error {
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

	h.auth = &Authenticator{
		Auther:  h.options.Auther,
		PR:      h.md.probeResistance,
		Realm:   h.md.authBasicRealm,
		Service: h.options.Service,
		Log:     h.options.Logger,
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

	if h.md.certificate != nil && h.md.privateKey != nil {
		h.certPool = tls_util.NewMemoryCertPool()
	}

	// Build the upstream transport that routes through the proxy chain.
	// DialContext uses h.dial which goes through h.options.Router.
	h.transport = &http.Transport{
		DialContext:           h.dial,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: h.md.readTimeout,
		DisableKeepAlives:     !h.md.keepalive,
		DisableCompression:    !h.md.compression,
	}

	return nil
}

// Handle processes an inbound connection. It reads one HTTP request,
// wraps the connection for stats, applies rate limiting, extracts the
// client IP, and delegates to handleRequest for routing.
//
// The connection is always closed when Handle returns.
func (h *httpHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Proto:      "http",
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

	// Save the raw conn before stats wrapping to preserve TLS metadata.
	rawConn := conn

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
			log.Error("record: %v", err)
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

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Error(err)
		return err
	}
	defer req.Body.Close()

	// Extract mTLS peer certificate from the raw connection.
	if peerCert := getTLSPeerCert(rawConn); peerCert != nil {
		ctx = xctx.ContextWithPeerCert(ctx, peerCert)
	}

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}

	conn = xnet.NewReadWriteConn(br, conn, conn)

	return h.handleRequest(ctx, conn, req, ro, log)
}

// handleRequest is the central request dispatcher. It normalises the request
// URL and host, extracts the target from GOST-compatible headers, validates
// the method, authenticates the client, applies bypass rules, and routes
// to one of three code paths:
//
//   - UDP: handleUDP
//   - HTTP forward proxy (GET/POST/…): handleProxy
//   - HTTP CONNECT tunnel: handleConnect
func (h *httpHandler) handleRequest(ctx context.Context, conn net.Conn, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	nr := normalizeRequest(req)
	network := nr.Network
	addr := nr.Addr
	ro.Network = network
	ro.Host = addr

	fields := map[string]any{
		"dst":     addr,
		"host":    addr,
		"network": network,
	}

	if u, _, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization")); u != "" {
		fields["user"] = u
		ro.ClientID = u
	}
	log = log.WithFields(fields)

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}
	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	// Build a skeleton response reused across error/auth/bypass writes.
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h.md.header,
		ContentLength: -1,
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}

	ro.HTTP = buildHTTPRecorder(req)
	defer func() {
		ro.HTTP.StatusCode = resp.StatusCode
		ro.HTTP.Response.Header = resp.Header
	}()

	// Authenticate before request validation so that probe resistance
	// can intercept non-proxy-form requests (e.g., browser/scanner probes
	// that send "GET / HTTP/1.1" instead of proxy-form URLs).
	result := h.auth.Authenticate(ctx, req)
	if !result.OK {
		if result.PipeTo != "" {
			return h.handleProbeResistanceHost(ctx, conn, req, result.PipeTo, log, resp)
		}
		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(result.Response, false)
			log.Trace(string(dump))
		}
		if result.Response.Body != nil {
			defer result.Response.Body.Close()
		}
		if err := result.Response.Write(conn); err != nil {
			log.Error("write auth response: ", err)
		}
		return errors.New("authentication failed")
	}

	// HTTP/2 connection preface "PRI * HTTP/2.0" is rejected, as are
	// non-CONNECT requests without an http:// scheme.
	if req.Method == "PRI" ||
		(req.Method != http.MethodConnect && req.URL.Scheme != "http") {
		resp.StatusCode = http.StatusBadRequest

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}

		return resp.Write(conn)
	}

	log = log.WithFields(map[string]any{"clientID": result.ClientID})
	ro.ClientID = result.ClientID

	if resp.Header.Get("Proxy-Agent") == "" {
		resp.Header.Set("Proxy-Agent", h.md.proxyAgent)
	}

	ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(result.ClientID))

	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, network, addr, bypass.WithService(h.options.Service)) {
		resp.StatusCode = http.StatusForbidden

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		log.Debug("bypass: ", addr)
		if err := resp.Write(conn); err != nil {
			log.Error("write bypass response: ", err)
		}
		return xbypass.ErrBypass
	}

	if network == "udp" {
		return h.handleUDP(ctx, conn, result.ClientID, ro, log)
	}

	conn, done := h.setupTrafficLimiter(conn, result.ClientID, network, addr)
	if done != nil {
		defer done()
	}

	if req.Method != http.MethodConnect {
		return h.handleProxy(ctx, conn, req, ro, log)
	}

	return h.handleConnect(ctx, conn, ro, log, addr, resp)
}

// Close cancels the background stats goroutine started in Init.
// It is safe to call on a handler that was never initialised.
func (h *httpHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

// buildHTTPRecorder creates an HTTPRecorderObject from the request metadata.
// The deferred status-code and response-header capture closure is set up by
// the caller (handleRequest) since it references the local resp variable.
func buildHTTPRecorder(req *http.Request) *xrecorder.HTTPRecorderObject {
	return &xrecorder.HTTPRecorderObject{
		Host:   req.Host,
		Proto:  req.Proto,
		Scheme: req.URL.Scheme,
		Method: req.Method,
		URI:    req.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: req.ContentLength,
			Header:        req.Header.Clone(),
		},
	}
}

// getTLSPeerCert extracts the verified mTLS client certificate identity from
// a connection by walking wrapper layers (traffic limiter, etc.) to reach the
// underlying *tls.Conn, then reading ConnectionState().VerifiedChains.
// It returns nil if the connection has no TLS peer certificate.
func getTLSPeerCert(conn net.Conn) *xctx.PeerCert {
	for {
		if tc, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			cs := tc.ConnectionState()
			if cs.HandshakeComplete && len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
				cert := cs.VerifiedChains[0][0]
				fpr := sha256.Sum256(cert.Raw)
				sans := make([]string, 0, len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.URIs))
				sans = append(sans, cert.DNSNames...)
				sans = append(sans, cert.EmailAddresses...)
				for _, u := range cert.URIs {
					sans = append(sans, u.String())
				}
				return &xctx.PeerCert{
					CN:          cert.Subject.CommonName,
					SANs:        sans,
					Fingerprint: hex.EncodeToString(fpr[:]),
				}
			}
			return nil
		}
		if uw, ok := conn.(interface{ UnwrapConn() net.Conn }); ok {
			conn = uw.UnwrapConn()
			continue
		}
		return nil
	}
}

// observeStats periodically publishes per-client traffic stats to the
// configured Observer. It runs in a background goroutine started by Init.
// Events that fail to send are retried on the next tick.
func (h *httpHandler) observeStats(ctx context.Context) {
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
