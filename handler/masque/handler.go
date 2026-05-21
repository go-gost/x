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

func init() {
	registry.HandlerRegistry().Register("masque", NewHandler)
}

var (
	ErrBadRequest         = errors.New("masque: bad request")
	ErrMethodNotAllowed   = errors.New("masque: method not allowed")
	ErrCapsuleRequired    = errors.New("masque: capsule-protocol header required")
	ErrDatagramNotSupport = errors.New("masque: datagrams not supported")
)

type masqueHandler struct {
	md       metadata
	options  handler.Options
	stats    *stats_util.HandlerStats
	limiter  traffic.TrafficLimiter
	cancel   context.CancelFunc
	recorder recorder.RecorderObject
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &masqueHandler{
		options: options,
	}
}

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

func (h *masqueHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "udp",
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

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

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

	// Extract request and response from context metadata
	ctxMd := ictx.MetadataFromContext(ctx)
	if ctxMd == nil {
		err := errors.New("masque: wrong connection type, requires HTTP/3")
		log.Error(err)
		return err
	}

	w, _ := ctxMd.Get("w").(http.ResponseWriter)
	r, _ := ctxMd.Get("r").(*http.Request)

	if w == nil || r == nil {
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
		return h.handleConnectUDP(ctx, w, r, conn.LocalAddr(), ro, log)
	case "HTTP/3.0", "":
		// Standard CONNECT for TCP (RFC 9114)
		// r.Proto is "HTTP/3.0" for standard HTTP/3 CONNECT (no :protocol header)
		ro.Network = "tcp"
		return h.handleConnectTCP(ctx, w, r, conn.LocalAddr(), ro, log)
	default:
		w.WriteHeader(http.StatusBadRequest)
		log.Errorf("masque: unsupported protocol: %s", r.Proto)
		return ErrBadRequest
	}
}

func (h *masqueHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

func (h *masqueHandler) handleConnectUDP(ctx context.Context, w http.ResponseWriter, r *http.Request, laddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	// Validate capsule-protocol header (required for CONNECT-UDP per RFC 9298)
	if r.Header.Get("Capsule-Protocol") != "?1" {
		w.WriteHeader(http.StatusBadRequest)
		log.Error(ErrCapsuleRequired)
		return ErrCapsuleRequired
	}

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

	// Get HTTP/3 stream for datagrams
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error(ErrDatagramNotSupport)
		return ErrDatagramNotSupport
	}

	// Send success response with capsule-protocol header
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)

	// Flush the response headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Get the underlying HTTP/3 stream
	stream := streamer.HTTPStream()

	// Resolve target address
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		log.Error("masque: failed to resolve target address: ", err)
		return err
	}

	// Create datagram connection wrapping the HTTP/3 stream (client side)
	datagramConn := masque_util.NewDatagramConn(stream, laddr, raddr)
	defer datagramConn.Close()

	// Wrap with traffic limiter
	var clientPC net.PacketConn = datagramConn
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

	// Relay UDP packets between client and target
	relay := udp.NewRelay(clientPC, targetPC).
		WithService(h.options.Service).
		WithLogger(log).
		WithBufferSize(h.md.bufferSize)

	return relay.Run(ctx)
}

func (h *masqueHandler) handleConnectTCP(ctx context.Context, w http.ResponseWriter, r *http.Request, laddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
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

	// Get HTTP/3 stream
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error("masque: failed to get HTTP/3 streamer")
		return errors.New("masque: HTTP/3 streamer not available")
	}

	// Dial target connection
	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: targetAddr})
	}

	var cc net.Conn
	var err error
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

	// Send 200 OK response
	w.WriteHeader(http.StatusOK)

	// Flush the response headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Get the underlying HTTP/3 stream
	stream := streamer.HTTPStream()

	// Resolve target address for StreamConn
	raddr, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		log.Error("masque: failed to resolve target address: ", err)
		return err
	}

	// Create stream connection wrapping the HTTP/3 stream
	streamConn := masque_util.NewStreamConn(stream, laddr, raddr)
	defer streamConn.Close()

	// Wrap with traffic limiter
	var clientConn net.Conn = streamConn
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
	xnet.Pipe(ctx, clientConn, cc)

	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, targetAddr)

	return nil
}

// fixedTargetPacketConn wraps a PacketConn and always reads/writes to a fixed target address
type fixedTargetPacketConn struct {
	net.PacketConn
	target net.Addr
}

func (c *fixedTargetPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, _, err = c.PacketConn.ReadFrom(b)
	return n, c.target, err
}

func (c *fixedTargetPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.PacketConn.WriteTo(b, c.target)
}

// connPacketConn wraps a net.Conn as a net.PacketConn for use with the UDP relay.
// This is used when the router returns a stream-based connection (like from masque connector).
type connPacketConn struct {
	net.Conn
	raddr net.Addr
}

func (c *connPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(b)
	return n, c.raddr, err
}

func (c *connPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Conn.Write(b)
}

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
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err == nil {
					events = nil
				}
				break
			}

			evs := h.stats.Events()
			if err := h.options.Observer.Observe(ctx, evs); err != nil {
				events = evs
			}

		case <-ctx.Done():
			return
		}
	}
}

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
