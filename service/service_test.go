package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
)

// --- Mocks ---

type mockListener struct {
	addr    net.Addr
	connCh  chan net.Conn // connections to deliver via Accept
	errCh   chan error    // errors to deliver via Accept
	closed  atomic.Bool
	closeMu sync.Mutex
	closeCh chan struct{}
}

func newMockListener() *mockListener {
	return &mockListener{
		addr:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		connCh:  make(chan net.Conn, 10),
		errCh:   make(chan error, 10),
		closeCh: make(chan struct{}),
	}
}

func (l *mockListener) Init(metadata.Metadata) error { return nil }

func (l *mockListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connCh:
		return c, nil
	case e := <-l.errCh:
		return nil, e
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

func (l *mockListener) Addr() net.Addr { return l.addr }

func (l *mockListener) Close() error {
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed.CompareAndSwap(false, true) {
		close(l.closeCh)
	}
	return nil
}

type mockHandler struct {
	handleFn func(ctx context.Context, conn net.Conn) error
	closed   atomic.Bool
}

func newMockHandler(fn func(ctx context.Context, conn net.Conn) error) *mockHandler {
	return &mockHandler{handleFn: fn}
}

func (h *mockHandler) Init(metadata.Metadata) error { return nil }

func (h *mockHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	if h.handleFn != nil {
		return h.handleFn(ctx, conn)
	}
	return nil
}

func (h *mockHandler) Close() error {
	h.closed.Store(true)
	return nil
}

type mockConn struct {
	net.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
	ctx        context.Context
	closed     atomic.Bool
}

func (c *mockConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *mockConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *mockConn) Close() error         { c.closed.Store(true); return nil }

type mockAdmission struct {
	allow bool
	calls atomic.Int32
}

func (a *mockAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	a.calls.Add(1)
	return a.allow
}

type mockObserver struct {
	events []observer.Event
	mu     sync.Mutex
	err    error
	closed atomic.Bool
}

func (o *mockObserver) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, events...)
	return o.err
}

func (o *mockObserver) Close() error {
	o.closed.Store(true)
	return nil
}

func (o *mockObserver) getEvents() []observer.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]observer.Event, len(o.events))
	copy(out, o.events)
	return out
}

type mockRecorder struct {
	recorded [][]byte
	mu       sync.Mutex
	err      error
}

func (r *mockRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	r.recorded = append(r.recorded, cp)
	return r.err
}

func (r *mockRecorder) getRecorded() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recorded
}

// --- NewService tests ---

func TestNewServiceDefaultsNopLogger(t *testing.T) {
	ln := newMockListener()
	h := newMockHandler(nil)
	svc := NewService("test", ln, h).(*defaultService)
	// Should not panic when logging
	svc.options.logger.Info("test")
}

func TestNewServiceSetsRunningState(t *testing.T) {
	ln := newMockListener()
	h := newMockHandler(nil)
	svc := NewService("test", ln, h).(*defaultService)
	if svc.Status().State() != StateRunning {
		t.Errorf("State() = %q, want %q", svc.Status().State(), StateRunning)
	}
}

func TestNewServiceRecordsCreateTime(t *testing.T) {
	before := time.Now()
	ln := newMockListener()
	h := newMockHandler(nil)
	svc := NewService("test", ln, h).(*defaultService)
	after := time.Now()

	ct := svc.Status().CreateTime()
	if ct.Before(before) || ct.After(after) {
		t.Errorf("CreateTime = %v, want between %v and %v", ct, before, after)
	}
}

// --- Addr tests ---

func TestAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080}
	ln := newMockListener()
	ln.addr = addr
	svc := NewService("test", ln, newMockHandler(nil)).(*defaultService)
	if got := svc.Addr(); got.String() != addr.String() {
		t.Errorf("Addr() = %v, want %v", got, addr)
	}
}

// --- Serve tests ---

func TestServeAcceptsConnection(t *testing.T) {
	ln := newMockListener()
	var handled atomic.Int32
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		handled.Add(1)
		return nil
	})
	svc := NewService("test", ln, h).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		localAddr:  ln.addr,
	}

	// Give handler goroutine time to run
	time.Sleep(100 * time.Millisecond)

	ln.Close()
	<-done

	if handled.Load() != 1 {
		t.Errorf("handled = %d, want 1", handled.Load())
	}
}

func TestServeSetsReadyState(t *testing.T) {
	ln := newMockListener()
	svc := NewService("test", ln, newMockHandler(nil)).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	time.Sleep(50 * time.Millisecond)
	if got := svc.Status().State(); got != StateReady {
		t.Errorf("State() = %q, want %q", got, StateReady)
	}

	ln.Close()
	<-done
}

func TestServeReturnsOnListenerClose(t *testing.T) {
	ln := newMockListener()
	svc := NewService("test", ln, newMockHandler(nil)).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.Close()
	err := <-done
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve() = %v, want net.ErrClosed", err)
	}

	if svc.Status().State() != StateClosed {
		t.Errorf("State() = %q, want %q", svc.Status().State(), StateClosed)
	}
}

func TestServeTemporaryErrorRetry(t *testing.T) {
	ln := newMockListener()
	svc := NewService("test", ln, newMockHandler(nil)).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	// Send a temporary error, then close
	ln.errCh <- &tempErr{}
	time.Sleep(50 * time.Millisecond)

	if svc.Status().State() != StateFailed {
		t.Errorf("State() = %q, want %q", svc.Status().State(), StateFailed)
	}

	ln.Close()
	<-done
}

type tempErr struct{}

func (tempErr) Error() string   { return "temporary error" }
func (tempErr) Temporary() bool { return true }
func (tempErr) Timeout() bool   { return false }

func TestServeAdmissionDeny(t *testing.T) {
	ln := newMockListener()
	var handled atomic.Int32
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		handled.Add(1)
		return nil
	})
	adm := &mockAdmission{allow: false}
	svc := NewService("test", ln, h, AdmissionOption(adm)).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
		localAddr:  ln.addr,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done

	if handled.Load() != 0 {
		t.Error("handler should not be called for denied connection")
	}
	if adm.calls.Load() != 1 {
		t.Errorf("admission calls = %d, want 1", adm.calls.Load())
	}
}

func TestServeAdmissionAllow(t *testing.T) {
	ln := newMockListener()
	var handled atomic.Int32
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		handled.Add(1)
		return nil
	})
	adm := &mockAdmission{allow: true}
	svc := NewService("test", ln, h, AdmissionOption(adm)).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
		localAddr:  ln.addr,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done

	if handled.Load() != 1 {
		t.Errorf("handled = %d, want 1", handled.Load())
	}
}

func TestServeHandlerErrorIncrementsStats(t *testing.T) {
	ln := newMockListener()
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		return errors.New("handler error")
	})
	ms := newMockStats()
	svc := NewService("test", ln, h, StatsOption(ms)).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
		localAddr:  ln.addr,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done

	if got := ms.Get(stats.KindTotalErrs); got != 1 {
		t.Errorf("TotalErrs = %d, want 1", got)
	}
}

func TestServeContextFromConn(t *testing.T) {
	ln := newMockListener()
	var gotSid string
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		if s := xctx.SidFromContext(ctx); s != "" {
			gotSid = string(s)
		}
		return nil
	})
	svc := NewService("test", ln, h).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
		localAddr:  ln.addr,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done

	if gotSid == "" {
		t.Error("expected session ID in context, got empty")
	}
}

func TestServeCtxConnContext(t *testing.T) {
	ln := newMockListener()
	wantCtx := context.Background()
	var gotCtx context.Context
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		gotCtx = ctx
		return nil
	})
	svc := NewService("test", ln, h).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &ctxConn{
		Conn: &mockConn{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
			localAddr:  ln.addr,
		},
		ctx: wantCtx,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done

	if gotCtx == nil {
		t.Fatal("handler context is nil")
	}
	// The ctx from the conn should be used as the base
	if s := xctx.SidFromContext(gotCtx); s == "" {
		t.Error("expected session ID to be added to conn context")
	}
}

type ctxConn struct {
	net.Conn
	ctx context.Context
}

func (c *ctxConn) Context() context.Context { return c.ctx }

func TestServeRecordsClientAddress(t *testing.T) {
	ln := newMockListener()
	rec := &mockRecorder{}
	h := newMockHandler(nil)

	svc := NewService("test", ln, h,
		RecordersOption(recorder.RecorderObject{
			Recorder: rec,
			Record:   recorder.RecorderServiceClientAddress,
		}),
	).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321},
		localAddr:  ln.addr,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done

	recorded := rec.getRecorded()
	if len(recorded) != 1 {
		t.Fatalf("recorded = %d entries, want 1", len(recorded))
	}
	if string(recorded[0]) != "192.168.1.100" {
		t.Errorf("recorded = %q, want %q", string(recorded[0]), "192.168.1.100")
	}
}

func TestServeRecordsClientAddressError(t *testing.T) {
	ln := newMockListener()
	rec := &mockRecorder{err: errors.New("record fail")}
	h := newMockHandler(nil)

	svc := NewService("test", ln, h,
		RecordersOption(recorder.RecorderObject{
			Recorder: rec,
			Record:   recorder.RecorderServiceClientAddress,
		}),
	).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	ln.connCh <- &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321},
		localAddr:  ln.addr,
	}

	time.Sleep(100 * time.Millisecond)
	ln.Close()
	<-done
	// Should not panic; error is just logged
}

func TestServeObserverStats(t *testing.T) {
	ln := newMockListener()
	obs := &mockObserver{}
	ms := newMockStats()
	h := newMockHandler(nil)

	svc := NewService("test", ln, h,
		ObserverOption(obs),
		StatsOption(ms),
		ObserverPeriodOption(50*time.Millisecond),
	).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	// Add some stats to trigger observation
	ms.Add(stats.KindTotalConns, 10)

	time.Sleep(200 * time.Millisecond)
	ln.Close()
	<-done

	events := obs.getEvents()
	if len(events) == 0 {
		t.Error("expected observer to receive events")
	}
}

// --- Close tests ---

func TestCloseClosesListener(t *testing.T) {
	ln := newMockListener()
	svc := NewService("test", ln, newMockHandler(nil))

	if err := svc.Close(); err != nil {
		t.Errorf("Close() = %v", err)
	}
	if !ln.closed.Load() {
		t.Error("listener was not closed")
	}
}

func TestCloseClosesHandler(t *testing.T) {
	ln := newMockListener()
	h := newMockHandler(nil)
	svc := NewService("test", ln, h).(*defaultService)

	if err := svc.Close(); err != nil {
		t.Errorf("Close() = %v", err)
	}
	if !h.closed.Load() {
		t.Error("handler was not closed")
	}
}

func TestCloseClosesObserver(t *testing.T) {
	ln := newMockListener()
	obs := &mockObserver{}
	svc := NewService("test", ln, newMockHandler(nil), ObserverOption(obs)).(*defaultService)

	if err := svc.Close(); err != nil {
		t.Errorf("Close() = %v", err)
	}
	if !obs.closed.Load() {
		t.Error("observer was not closed")
	}
}

func TestCloseJoinsErrors(t *testing.T) {
	ln := newMockListener()
	h := &closeErrHandler{err: errors.New("handler close error")}
	svc := NewService("test", ln, h).(*defaultService)

	err := svc.Close()
	if err == nil {
		t.Fatal("Close() = nil, want error")
	}
	if err.Error() != "handler close error" {
		t.Errorf("Close() = %v, want 'handler close error'", err)
	}
}

type closeErrHandler struct {
	err error
}

func (h *closeErrHandler) Init(metadata.Metadata) error                { return nil }
func (h *closeErrHandler) Handle(context.Context, net.Conn, ...handler.HandleOption) error {
	return nil
}
func (h *closeErrHandler) Close() error { return h.err }

// --- Status tests ---

func TestStatusReturnsStatus(t *testing.T) {
	ln := newMockListener()
	svc := NewService("test", ln, newMockHandler(nil)).(*defaultService)
	st := svc.Status()
	if st == nil {
		t.Fatal("Status() = nil")
	}
	if st.State() != StateRunning {
		t.Errorf("State() = %q, want %q", st.State(), StateRunning)
	}
}

// --- ServiceEvent tests ---

func TestServiceEventType(t *testing.T) {
	ev := ServiceEvent{Kind: "service", Service: "test", State: StateReady}
	if ev.Type() != observer.EventStatus {
		t.Errorf("Type() = %v, want %v", ev.Type(), observer.EventStatus)
	}
}

// --- Integration: multiple connections ---

func TestServeMultipleConnections(t *testing.T) {
	ln := newMockListener()
	var handled atomic.Int32
	h := newMockHandler(func(ctx context.Context, conn net.Conn) error {
		handled.Add(1)
		return nil
	})
	svc := NewService("test", ln, h).(*defaultService)

	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()

	for i := 0; i < 5; i++ {
		ln.connCh <- &mockConn{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1000 + i},
			localAddr:  ln.addr,
		}
	}

	time.Sleep(200 * time.Millisecond)
	ln.Close()
	<-done

	if got := handled.Load(); got != 5 {
		t.Errorf("handled = %d, want 5", got)
	}
}

// --- execCmd tests ---

func TestExecCmdInvalidCommand(t *testing.T) {
	svc := NewService("test", newMockListener(), newMockHandler(nil)).(*defaultService)
	err := svc.execCmd("")
	if err == nil {
		t.Error("execCmd('') = nil, want error")
	}
}

// --- Interface assertions ---

var _ io.Closer = (*closeErrHandler)(nil)
var _ listener.Listener = (*mockListener)(nil)
var _ handler.Handler = (*mockHandler)(nil)
var _ handler.Handler = (*closeErrHandler)(nil)
var _ admission.Admission = (*mockAdmission)(nil)
var _ observer.Observer = (*mockObserver)(nil)
var _ stats.Stats = (*mockStats)(nil)
var _ recorder.Recorder = (*mockRecorder)(nil)
var _ xctx.Context = (*ctxConn)(nil)
