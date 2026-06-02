package relay

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/relay"
	xbypass "github.com/go-gost/x/bypass"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
)

// ---------------------------------------------------------------------------
// newInitdHandler — convenience: construct + Init
// ---------------------------------------------------------------------------

func newInitdHandler(t *testing.T, opts ...handler.Option) *relayHandler {
	t.Helper()
	// Ensure a logger is always set
	h := NewHandler(append([]handler.Option{handler.LoggerOption(&testLogger{})}, opts...)...).(*relayHandler)
	if err := h.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return h
}

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler_Minimal(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("handler is nil")
	}
	rh := h.(*relayHandler)
	if rh.options.Service != "" {
		t.Errorf("Service = %q, want empty", rh.options.Service)
	}
}

func TestNewHandler_WithOptions(t *testing.T) {
	log := &testLogger{}
	h := NewHandler(
		handler.LoggerOption(log),
		handler.ServiceOption("test-svc"),
	)
	rh := h.(*relayHandler)
	if rh.options.Logger == nil {
		t.Error("Logger not set")
	}
	if rh.options.Service != "test-svc" {
		t.Errorf("Service = %q, want test-svc", rh.options.Service)
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func TestInit_Minimal(t *testing.T) {
	rh := NewHandler().(*relayHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.cancel == nil {
		t.Error("cancel is nil")
	}
	if rh.stats != nil {
		t.Error("stats should be nil (no observer)")
	}
	if rh.limiter != nil {
		t.Error("limiter should be nil (no limiter)")
	}
}

func TestInit_WithObserver(t *testing.T) {
	fakeObs := &fakeObserver{eventsCh: make(chan []observer.Event, 10)}
	rh := NewHandler(
		handler.ObserverOption(fakeObs),
		handler.ServiceOption("test-svc"),
	).(*relayHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.stats == nil {
		t.Error("stats should be non-nil (observer set)")
	}
}

func TestInit_WithLimiter(t *testing.T) {
	ml := &mockTrafficLimiter{}
	rh := NewHandler(
		handler.TrafficLimiterOption(ml),
	).(*relayHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.limiter == nil {
		t.Error("limiter should be non-nil")
	}
}

func TestInit_WithRecorder(t *testing.T) {
	rec := recorder.RecorderObject{
		Record:   xrecorder.RecorderServiceHandler,
		Recorder: &dummyRecorder{},
	}
	rh := NewHandler(
		handler.RecordersOption(rec),
	).(*relayHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.recorder.Recorder == nil {
		t.Error("recorder should be non-nil")
	}
}

func TestInit_CertPoolNilWithoutCerts(t *testing.T) {
	rh := NewHandler().(*relayHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.certPool != nil {
		t.Error("certPool should be nil (no certs configured)")
	}
}

// ---------------------------------------------------------------------------
// Forward
// ---------------------------------------------------------------------------

func TestForward_SetsHop(t *testing.T) {
	rh := newInitdHandler(t)
	mh := &mockHop{}
	rh.Forward(mh)
	if rh.hop != mh {
		t.Error("hop not set")
	}
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestClose_CancelsContext(t *testing.T) {
	rh := newInitdHandler(t)
	if rh.cancel == nil {
		t.Fatal("cancel is nil")
	}
	if err := rh.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Double close is safe
	if err := rh.Close(); err != nil {
		t.Errorf("Close (second): %v", err)
	}
}

func TestClose_WithoutInit(t *testing.T) {
	rh := NewHandler().(*relayHandler)
	if err := rh.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Handle — error cases
// ---------------------------------------------------------------------------

func TestHandle_BadVersion(t *testing.T) {
	rh := newInitdHandler(t)

	req := relay.Request{Version: 0xFF, Cmd: relay.CmdConnect}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fc := &fakeConn{buf: buf.Bytes()}
	err := rh.Handle(context.Background(), fc)
	// The relay library's Request.ReadFrom returns ErrBadVersion on version
	// mismatch before the handler can write a response. The error is returned
	// directly without a response frame.
	if err == nil {
		t.Fatal("expected error")
	}
	// No response is written because ReadFrom fails before the handler's
	// version check in Handle.
}

func TestHandle_UnknownCmd(t *testing.T) {
	rh := newInitdHandler(t)

	req := relay.Request{Version: relay.Version1, Cmd: 0xFF}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fc := &fakeConn{buf: buf.Bytes()}
	err := rh.Handle(context.Background(), fc)
	if err == nil || err.Error() != "relay: unknown command" {
		t.Errorf("err = %v, want relay: unknown command", err)
	}
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusBadRequest {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusBadRequest)
	}
}

func TestHandle_EmptyAddress(t *testing.T) {
	rh := newInitdHandler(t)

	// Build a connect request with an AddrFeature that has empty host
	req := relay.Request{Version: relay.Version1, Cmd: relay.CmdConnect}
	req.Features = append(req.Features, &relay.AddrFeature{})
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fc := &fakeConn{buf: buf.Bytes()}
	err := rh.Handle(context.Background(), fc)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandle_WithBypass(t *testing.T) {
	mb := &mockBypass{
		containsFn: func(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
			return true
		},
	}
	rh := newInitdHandler(t, handler.BypassOption(mb))

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != xbypass.ErrBypass {
		t.Errorf("err = %v, want %v", err, xbypass.ErrBypass)
	}
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusForbidden {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusForbidden)
	}
}

func TestHandle_Unauthorized(t *testing.T) {
	ma := &mockAuther{
		authenticateFn: func(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
			return "", false
		},
	}
	rh := newInitdHandler(t, handler.AutherOption(ma))

	req := relay.Request{Version: relay.Version1, Cmd: relay.CmdConnect}
	req.Features = append(req.Features, &relay.UserAuthFeature{Username: "user", Password: "pass"})
	af := &relay.AddrFeature{}
	af.ParseFrom("example.com:80")
	req.Features = append(req.Features, af)
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fc := &fakeConn{buf: buf.Bytes()}
	err := rh.Handle(context.Background(), fc)
	if err == nil || err.Error() != "relay: unauthorized" {
		t.Errorf("err = %v, want relay: unauthorized", err)
	}
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusUnauthorized)
	}
}

func TestHandle_Authorized(t *testing.T) {
	ma := &mockAuther{
		authenticateFn: func(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
			return "client-1", true
		},
	}
	mr := &mockRouter{
		dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
			pr, pw := net.Pipe()
			pw.Close()
			return pr, nil
		},
	}
	rh := newInitdHandler(t,
		handler.AutherOption(ma),
		handler.RouterOption(mr),
	)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestHandle_RateLimited(t *testing.T) {
	mrc := &mockRateLimiterContainer{
		limiterFn: func(key string) rate.Limiter {
			return &mockRateLimiter{
				allowFn: func(n int) bool { return false },
			}
		},
	}
	rh := NewHandler(
		handler.RateLimiterOption(mrc),
		handler.LoggerOption(&testLogger{}),
	).(*relayHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	fc := &fakeConn{}
	err := rh.Handle(context.Background(), fc)
	if err != rate_limiter.ErrRateLimit {
		t.Errorf("err = %v, want %v", err, rate_limiter.ErrRateLimit)
	}
}

func TestHandle_ReadTimeout(t *testing.T) {
	h := &relayHandler{
		options: handler.Options{Logger: &testLogger{}},
	}
	h.parseMetadata(testMD(map[string]any{"readTimeout": "100ms"}))

	fc := &fakeConn{}
	err := h.Handle(context.Background(), fc)
	if err == nil {
		t.Error("expected error from read timeout")
	}
}

func TestHandle_ContextCancelled(t *testing.T) {
	mr := &mockRouter{
		dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
			pr, _ := net.Pipe()
			return pr, nil
		},
	}
	rh := newInitdHandler(t, handler.RouterOption(mr))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	// The request is read from conn first (which succeeds because fakeConn has data),
	// then handleConnect tries to dial, which may fail if ctx is cancelled.
	// This test verifies no panic occurs with cancelled context.
	err := rh.Handle(ctx, fc)
	_ = err // may or may not error depending on router dial behavior
}

// ---------------------------------------------------------------------------
// Handle — forward mode
// ---------------------------------------------------------------------------

func TestHandle_ForwardMode_NoTarget(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return nil
		},
	}
	rh := newInitdHandler(t, handler.RouterOption(&mockRouter{}))
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err == nil || err.Error() != "target not available" {
		t.Errorf("err = %v, want target not available", err)
	}
}

func TestHandle_ForwardMode_TargetFound(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return makeTestNode("example.com:80")
		},
	}
	mr := &mockRouter{
		dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
			pr, pw := net.Pipe()
			pw.Close()
			return pr, nil
		},
	}
	rh := newInitdHandler(t, handler.RouterOption(mr))
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

// ---------------------------------------------------------------------------
// observeStats
// ---------------------------------------------------------------------------

func TestObserveStats_NilObserver(t *testing.T) {
	rh := &relayHandler{}
	rh.observeStats(context.Background()) // should not panic
}

func TestObserveStats_NormalTick(t *testing.T) {
	obs := &fakeObserver{eventsCh: make(chan []observer.Event, 10)}
	rh := &relayHandler{
		options: handler.Options{Observer: obs, Logger: &testLogger{}},
		md:      metadata{observerPeriod: 50 * time.Millisecond},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	rh.observeStats(ctx)
}

func TestObserveStats_Cancel(t *testing.T) {
	obs := &fakeObserver{eventsCh: make(chan []observer.Event, 10)}
	rh := &relayHandler{
		options: handler.Options{Observer: obs},
		md:      metadata{observerPeriod: time.Hour},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rh.observeStats(ctx) // should return immediately
}

// ---------------------------------------------------------------------------
// checkRateLimit
// ---------------------------------------------------------------------------

func TestCheckRateLimit_NoLimiter(t *testing.T) {
	rh := &relayHandler{}
	if !rh.checkRateLimit(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}) {
		t.Error("should allow when no rate limiter")
	}
}

func TestCheckRateLimit_NoLimiterForKey(t *testing.T) {
	mrc := &mockRateLimiterContainer{
		limiterFn: func(key string) rate.Limiter { return nil },
	}
	rh := &relayHandler{
		options: handler.Options{RateLimiter: mrc},
	}
	if !rh.checkRateLimit(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}) {
		t.Error("should allow when no limiter for key")
	}
}

func TestCheckRateLimit_LimiterDenies(t *testing.T) {
	mrc := &mockRateLimiterContainer{
		limiterFn: func(key string) rate.Limiter {
			return &mockRateLimiter{
				allowFn: func(n int) bool { return false },
			}
		},
	}
	rh := &relayHandler{
		options: handler.Options{RateLimiter: mrc},
	}
	if rh.checkRateLimit(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}) {
		t.Error("should deny when limiter says no")
	}
}

// ---------------------------------------------------------------------------
// dummyRecorder
// ---------------------------------------------------------------------------

type dummyRecorder struct{}

func (r *dummyRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	return nil
}