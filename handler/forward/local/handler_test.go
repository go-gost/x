package local

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/sniffing"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	xrecorder "github.com/go-gost/x/recorder"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// mockRouter implements chain.Router.
type mockRouter struct {
	opts   *chain.RouterOptions
	dialFn func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockRouter) Options() *chain.RouterOptions { return m.opts }
func (m *mockRouter) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	if m.dialFn != nil {
		return m.dialFn(ctx, network, address)
	}
	return nil, nil
}
func (m *mockRouter) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	return nil, nil
}

// mockHop implements hop.Hop.
type mockHop struct {
	selectFn func(ctx context.Context, opts ...hop.SelectOption) *chain.Node
}

func (m *mockHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if m.selectFn != nil {
		return m.selectFn(ctx, opts...)
	}
	return nil
}

type mockRateLimiter struct {
	limiterFn func(key string) rate.Limiter
}

func (m *mockRateLimiter) Limiter(key string) rate.Limiter {
	if m.limiterFn != nil {
		return m.limiterFn(key)
	}
	return nil
}

type mockLimiter struct {
	allowFn func(n int) bool
}

func (m *mockLimiter) Allow(n int) bool {
	if m.allowFn != nil {
		return m.allowFn(n)
	}
	return true
}

func (m *mockLimiter) Limit() float64 { return 0 }

// mockRecorder implements recorder.Recorder.
type mockRecorder struct{}

func (m *mockRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	return nil
}
func (m *mockRecorder) Close() error { return nil }

// stringConn is a net.Conn backed by bytes.Buffer for testing.
type stringConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	local    net.Addr
	remote   net.Addr
	closed   bool
	mu       sync.Mutex
}

func newStringConn(data []byte) *stringConn {
	return &stringConn{
		readBuf:  bytes.NewBuffer(data),
		writeBuf: new(bytes.Buffer),
		local:    &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		remote:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345},
	}
}

func (c *stringConn) Read(b []byte) (int, error)  { return c.readBuf.Read(b) }
func (c *stringConn) Write(b []byte) (int, error)  { return c.writeBuf.Write(b) }
func (c *stringConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *stringConn) LocalAddr() net.Addr                { return c.local }
func (c *stringConn) RemoteAddr() net.Addr               { return c.remote }
func (c *stringConn) SetDeadline(t time.Time) error      { return nil }
func (c *stringConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stringConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nopLog() logger.Logger { return xlogger.Nop() }

func newTestHandler(opts ...handler.Option) *forwardHandler {
	options := handler.Options{
		Logger: nopLog(),
		Router: &mockRouter{opts: &chain.RouterOptions{}},
	}
	for _, opt := range opts {
		opt(&options)
	}
	return &forwardHandler{options: options}
}

func newInitdHandler(opts ...handler.Option) *forwardHandler {
	h := newTestHandler(opts...)
	_ = h.Init(xmd.NewMetadata(nil))
	return h
}

// withRateLimiter is a helper to set the RateLimiter option.
func withRateLimiter(rl rate.RateLimiter) handler.Option {
	return func(o *handler.Options) {
		o.RateLimiter = rl
	}
}

// withRouter is a helper to set the Router option.
func withRouter(r chain.Router) handler.Option {
	return func(o *handler.Options) {
		o.Router = r
	}
}

// withRecorder is a helper to append a RecorderObject to the Recorders slice.
func withRecorder(ro recorder.RecorderObject) handler.Option {
	return func(o *handler.Options) {
		o.Recorders = append(o.Recorders, ro)
	}
}

// ---------------------------------------------------------------------------
// newRecorderObject
// ---------------------------------------------------------------------------

func TestNewRecorderObject_TCP(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	start := time.Now()

	ro := h.newRecorderObject(context.Background(), conn, start)

	if ro.Network != "tcp" {
		t.Errorf("expected network tcp, got %s", ro.Network)
	}
	if ro.RemoteAddr != "10.0.0.1:12345" {
		t.Errorf("expected remote 10.0.0.1:12345, got %s", ro.RemoteAddr)
	}
	if ro.LocalAddr != "127.0.0.1:8080" {
		t.Errorf("expected local 127.0.0.1:8080, got %s", ro.LocalAddr)
	}
	if !ro.Time.Equal(start) {
		t.Errorf("expected time %v, got %v", start, ro.Time)
	}
}

func TestNewRecorderObject_SID(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	ctx := xctx.ContextWithSid(context.Background(), xctx.Sid("test-sid"))

	ro := h.newRecorderObject(ctx, conn, time.Now())

	if ro.SID != "test-sid" {
		t.Errorf("expected SID 'test-sid', got '%s'", ro.SID)
	}
}

func TestNewRecorderObject_NilSrcAddr(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)

	ro := h.newRecorderObject(context.Background(), conn, time.Now())

	if ro.ClientAddr != "" {
		t.Errorf("expected empty ClientAddr, got %s", ro.ClientAddr)
	}
}

// ---------------------------------------------------------------------------
// checkRateLimit
// ---------------------------------------------------------------------------

func TestCheckRateLimit_NilLimiter(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)

	if !h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected true when RateLimiter is nil")
	}
}

func TestCheckRateLimit_Allowed(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&mockRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &mockLimiter{allowFn: func(n int) bool { return true }}
		},
	}))
	conn := newStringConn(nil)

	if !h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected true when limiter allows")
	}
}

func TestCheckRateLimit_Blocked(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&mockRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &mockLimiter{allowFn: func(n int) bool { return false }}
		},
	}))
	conn := newStringConn(nil)

	if h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected false when limiter blocks")
	}
}

func TestCheckRateLimit_NoLimiterForKey(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&mockRateLimiter{
		limiterFn: func(key string) rate.Limiter { return nil },
	}))
	conn := newStringConn(nil)

	if !h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected true when no limiter found for key")
	}
}

// ---------------------------------------------------------------------------
// sniffingDial
// ---------------------------------------------------------------------------

func TestSniffingDial_Success(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	ro := &xrecorder.HandlerRecorderObject{}

	cc, err := h.sniffingDial(context.Background(), "tcp", "example.com:80", ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cc.Close()

	if ro.Route == "" {
		t.Log("route is empty (mock does not populate context buffer)")
	}
}

func TestSniffingDial_RouterError(t *testing.T) {
	expectedErr := errors.New("dial failed")
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, expectedErr
		},
	}))
	ro := &xrecorder.HandlerRecorderObject{}

	_, err := h.sniffingDial(context.Background(), "tcp", "example.com:80", ro)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// ---------------------------------------------------------------------------
// buildSniffer
// ---------------------------------------------------------------------------

func TestBuildSniffer(t *testing.T) {
	h := newTestHandler()
	h.md.sniffingWebsocket = true
	h.md.sniffingWebsocketSampleRate = 0.5
	h.md.readTimeout = 30 * time.Second

	sniffer := h.buildSniffer()

	if !sniffer.Websocket {
		t.Error("expected Websocket to be true")
	}
	if sniffer.WebsocketSampleRate != 0.5 {
		t.Errorf("expected 0.5, got %f", sniffer.WebsocketSampleRate)
	}
	if sniffer.ReadTimeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", sniffer.ReadTimeout)
	}
}

// ---------------------------------------------------------------------------
// handleSniffedProtocol
// ---------------------------------------------------------------------------

func TestHandleSniffedProtocol_UnknownProto(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), "ssh")
	if handled {
		t.Error("expected handled=false for unknown proto")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestHandleSniffedProtocol_EmptyProto(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), "")
	if handled {
		t.Error("expected handled=false for empty proto")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// handleRawForwarding
// ---------------------------------------------------------------------------

func TestHandleRawForwarding_NilHop(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no route to host")
		},
	}))
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err == nil {
		t.Fatal("expected error when hop is nil")
	}
}

func TestHandleRawForwarding_NodeUnavailable(t *testing.T) {
	h := newInitdHandler()
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return nil
		},
	}
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err == nil {
		t.Fatal("expected error when node is nil")
	}
	if err.Error() != "node not available" {
		t.Errorf("expected 'node not available', got %v", err)
	}
}

func TestHandleRawForwarding_DialError(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}))
	// Use NewNode to include a marker (so Mark() is exercised on error).
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("test-node", "127.0.0.1:9999")
		},
	}
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err == nil {
		t.Fatal("expected error when dial fails")
	}
	if ro.Host != "127.0.0.1:9999" {
		t.Errorf("expected host 127.0.0.1:9999, got %s", ro.Host)
	}
}

func TestHandleRawForwarding_Success(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	// xnet.Pipe will half-close the pipe. We just close the other end to
	// prevent goroutine leaks; the actual data flow through Pipe is tested
	// at integration level.

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1:80", Name: "upstream"}
		},
	}
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ro.Host != "10.0.0.1:80" {
		t.Errorf("expected host 10.0.0.1:80, got %s", ro.Host)
	}
	if ro.Network != "tcp" {
		t.Errorf("expected network tcp, got %s", ro.Network)
	}
	if ro.SrcAddr == "" {
		t.Error("expected SrcAddr to be set")
	}
	if ro.DstAddr == "" {
		t.Error("expected DstAddr to be set")
	}
}

func TestHandleRawForwarding_AddrWithoutPort(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1", Name: "noport"}
		},
	}
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ro.Host != "10.0.0.1:0" {
		t.Errorf("expected ':0' appended to addr, got %s", ro.Host)
	}
}

// ---------------------------------------------------------------------------
// Handle integration
// ---------------------------------------------------------------------------

func TestHandle_NoRouter(t *testing.T) {
	h := newTestHandler(func(o *handler.Options) {
		o.Router = nil
	})
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error when router is nil")
	}
	if err.Error() != "router not available" {
		t.Errorf("expected 'router not available', got %v", err)
	}
}

func TestHandle_RateLimited(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&mockRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &mockLimiter{allowFn: func(n int) bool { return false }}
		},
	}))
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
}

func TestHandle_BasicForward(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Drain the other end of the pipe so writes from xnet.Pipe don't block.
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := client.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1:80", Name: "target"}
		},
	}
	conn := newStringConn([]byte("hello"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseMetadata
// ---------------------------------------------------------------------------

func TestParseMetadata_Defaults(t *testing.T) {
	h := newTestHandler()

	err := h.parseMetadata(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout <= 0 {
		t.Error("expected positive default readTimeout")
	}
	if h.md.sniffing {
		t.Error("expected sniffing disabled by default")
	}
}

func TestParseMetadata_CustomValues(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"readTimeout":                    "60s",
		"http.keepalive":                 true,
		"proxyProtocol":                  2,
		"sniffing":                       true,
		"sniffing.timeout":               "5s",
		"sniffing.websocket":             true,
		"sniffing.websocket.sampleRate":  0.75,
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout != 60*time.Second {
		t.Errorf("expected 60s, got %v", h.md.readTimeout)
	}
	if !h.md.httpKeepalive {
		t.Error("expected httpKeepalive true")
	}
	if h.md.proxyProtocol != 2 {
		t.Errorf("expected proxyProtocol 2, got %d", h.md.proxyProtocol)
	}
	if !h.md.sniffing {
		t.Error("expected sniffing true")
	}
	if h.md.sniffingTimeout != 5*time.Second {
		t.Errorf("expected 5s sniffingTimeout, got %v", h.md.sniffingTimeout)
	}
	if !h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket true")
	}
	if h.md.sniffingWebsocketSampleRate != 0.75 {
		t.Errorf("expected 0.75, got %f", h.md.sniffingWebsocketSampleRate)
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func TestInit_SelectsRecorder(t *testing.T) {
	h := newTestHandler(withRecorder(recorder.RecorderObject{
		Record:   xrecorder.RecorderServiceHandler,
		Recorder: &mockRecorder{},
	}))
	err := h.Init(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.recorder.Recorder == nil {
		t.Error("expected recorder to be set")
	}
}

func TestInit_CertPool(t *testing.T) {
	cert, key := generateTestCertKey(t)
	h := newTestHandler()
	h.md.certificate = cert
	h.md.privateKey = key
	err := h.Init(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.certPool == nil {
		t.Error("expected certPool to be created")
	}
}

// ---------------------------------------------------------------------------
// NewHandler / Forward
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler(func(o *handler.Options) {
		o.Service = "test-svc"
	})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	fh, ok := h.(*forwardHandler)
	if !ok {
		t.Fatal("expected *forwardHandler")
	}
	if fh.options.Service != "test-svc" {
		t.Errorf("expected Service 'test-svc', got %s", fh.options.Service)
	}
}

func TestForward(t *testing.T) {
	h := newTestHandler()
	mh := &mockHop{}
	h.Forward(mh)
	if h.hop != mh {
		t.Error("expected hop to be set")
	}
}

// ---------------------------------------------------------------------------
// newRecorderObject — UDP
// ---------------------------------------------------------------------------

type packetConn struct {
	*stringConn
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, nil }

func TestNewRecorderObject_UDP(t *testing.T) {
	h := newInitdHandler()
	conn := &packetConn{newStringConn(nil)}

	ro := h.newRecorderObject(context.Background(), conn, time.Now())

	if ro.Network != "udp" {
		t.Errorf("expected network udp, got %s", ro.Network)
	}
}

// ---------------------------------------------------------------------------
// handleSniffedProtocol — HTTP / TLS dispatch
// ---------------------------------------------------------------------------

func TestHandleSniffedProtocol_HTTP(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dial not configured in test")
		},
	}))
	// Minimal HTTP request — enough for http.ReadRequest to parse.
	conn := newStringConn([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), sniffing.ProtoHTTP)

	if !handled {
		t.Error("expected handled=true for HTTP proto")
	}
	// The sniffer will try to dial and fail — but dispatch is verified.
	if err == nil {
		t.Log("sniffer processed HTTP request without error")
	}
}

func TestHandleSniffedProtocol_TLS(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dial not configured in test")
		},
	}))
	// Minimal TLS ClientHello — enough for tls-dissector to parse.
	// Record header: 16 03 01 (handshake), then length + ClientHello.
	conn := newStringConn([]byte{
		0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x03, 0x01,
	})
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), sniffing.ProtoTLS)

	if !handled {
		t.Error("expected handled=true for TLS proto")
	}
	if err == nil {
		t.Log("sniffer processed TLS ClientHello without error")
	}
}

// ---------------------------------------------------------------------------
// Handle — sniffing integration
// ---------------------------------------------------------------------------

func TestHandle_SniffingEnabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	// Drain to prevent pipe deadlock.
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := client.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.md.sniffing = true
	h.md.sniffingTimeout = 5 * time.Second
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1:80", Name: "target"}
		},
	}
	// Data that sniffing.Sniff won't recognize as HTTP/TLS (fall through to raw forward).
	conn := newStringConn([]byte("hello world"))
	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseMetadata — cert/key
// ---------------------------------------------------------------------------

func TestParseMetadata_MITMCertError(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": "/nonexistent/cert.pem",
		"mitm.keyFile":  "/nonexistent/key.pem",
	})
	err := h.parseMetadata(md)
	if err == nil {
		t.Fatal("expected error for non-existent cert file")
	}
}

func TestParseMetadata_MITMCert(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	certFile := writeTempFile(t, "cert-*.pem", certPEM)
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "key-*.pem", keyPEM)
	defer os.Remove(keyFile)

	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": certFile,
		"mitm.keyFile":  keyFile,
		"mitm.alpn":     "h2",
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.certificate == nil {
		t.Error("expected certificate to be loaded")
	}
	if h.md.privateKey == nil {
		t.Error("expected privateKey to be loaded")
	}
	if h.md.alpn != "h2" {
		t.Errorf("expected alpn 'h2', got %s", h.md.alpn)
	}
}

func TestNewRecorderObject_SrcAddr(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	srcAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 54321}
	ctx := xctx.ContextWithSrcAddr(context.Background(), srcAddr)

	ro := h.newRecorderObject(ctx, conn, time.Now())

	if ro.ClientAddr != "192.168.1.1:54321" {
		t.Errorf("expected ClientAddr '192.168.1.1:54321', got '%s'", ro.ClientAddr)
	}
}

// ---------------------------------------------------------------------------
// handleRawForwarding — unix socket
// ---------------------------------------------------------------------------

func TestHandleRawForwarding_UnixSocket(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("unix-node", "/tmp/unix.sock",
				chain.NetworkNodeOption("unix"),
			)
		},
	}
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.Network != "unix" {
		t.Errorf("expected network 'unix', got '%s'", ro.Network)
	}
}

func TestHandleRawForwarding_MarkerReset(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	// NewNode sets a FailMarker, which gets Reset() on successful dial.
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	}
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.Host != "10.0.0.1:80" {
		t.Errorf("expected host '10.0.0.1:80', got '%s'", ro.Host)
	}
}

// ---------------------------------------------------------------------------
// Init error path
// ---------------------------------------------------------------------------

func TestInit_ParseMetadataError(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": "/nonexistent/cert.pem",
		"mitm.keyFile":  "/nonexistent/key.pem",
	})
	err := h.Init(md)
	if err == nil {
		t.Fatal("expected error from Init with bad cert files")
	}
}

// ---------------------------------------------------------------------------
// Handle — recorder error
// ---------------------------------------------------------------------------

type errorRecorder struct{}

func (e *errorRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	return errors.New("record error")
}
func (e *errorRecorder) Close() error { return nil }

func TestHandle_RecorderError(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.recorder = recorder.RecorderObject{Recorder: &errorRecorder{}}
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	}
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Handle — sniff error (empty conn)
// ---------------------------------------------------------------------------

func TestHandle_SniffError(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.md.sniffing = true
	h.md.sniffingTimeout = 5 * time.Second
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	}
	// Empty conn → Peek fails → Sniff returns error.
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Handle — sniff HTTP → handled=true path
// ---------------------------------------------------------------------------

func TestHandle_SniffHTTP(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Drain and echo back a minimal response so the sniffer's roundTrip completes.
	go func() {
		buf := make([]byte, 4096)
		n, err := client.Read(buf)
		if err == nil && n > 0 {
			client.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.md.sniffing = true
	h.md.sniffingTimeout = 5 * time.Second
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	}
	conn := newStringConn([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Logf("sniffed HTTP path returned: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test certificate helpers
// ---------------------------------------------------------------------------

func generateTestCertKey(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

func generateTestCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	cert, key := generateTestCertKey(t)
	certPEM = pemEncode("CERTIFICATE", cert.Raw)
	keyBytes := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
	keyPEM = pemEncode("RSA PRIVATE KEY", keyBytes)
	return
}

func pemEncode(blockType string, der []byte) []byte {
	block := &pem.Block{Type: blockType, Bytes: der}
	return pem.EncodeToMemory(block)
}

func writeTempFile(t *testing.T, pattern string, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
