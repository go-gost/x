package router

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/relay"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// newInitdHandler — convenience constructor with minimal Init
// ---------------------------------------------------------------------------

func newInitdHandler(t *testing.T, opts ...handler.Option) *routerHandler {
	t.Helper()
	h := NewHandler(append([]handler.Option{
		handler.LoggerOption(&testLogger{}),
	}, opts...)...).(*routerHandler)
	if err := h.parseMetadata(testMD(nil)); err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	h.id = uuid.New().String()
	h.log = &testLogger{}
	h.pool = NewConnectorPool(h.id)
	_, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	return h
}

// ---------------------------------------------------------------------------
// NewHandler tests
// ---------------------------------------------------------------------------

func TestNewHandler_Minimal(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("handler is nil")
	}
	rh := h.(*routerHandler)
	if rh.options.Service != "" {
		t.Errorf("Service = %q, want empty", rh.options.Service)
	}
	if rh.sdCache == nil {
		t.Error("sdCache is nil")
	}
	if rh.routeCache == nil {
		t.Error("routeCache is nil")
	}
}

func TestNewHandler_WithOptions(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
		handler.ServiceOption("test-svc"),
	)
	rh := h.(*routerHandler)
	if rh.options.Logger == nil {
		t.Error("Logger not set")
	}
	if rh.options.Service != "test-svc" {
		t.Errorf("Service = %q, want test-svc", rh.options.Service)
	}
}

// ---------------------------------------------------------------------------
// Init tests
// ---------------------------------------------------------------------------

func TestInit_Minimal(t *testing.T) {
	rh := NewHandler(handler.LoggerOption(&testLogger{})).(*routerHandler)
	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.id == "" {
		t.Error("id is empty")
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
	obs := newFakeObserver(10)
	rh := NewHandler(
		handler.LoggerOption(&testLogger{}),
		handler.ObserverOption(obs),
		handler.ServiceOption("test-svc"),
	).(*routerHandler)

	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.stats == nil {
		t.Error("stats should be non-nil when observer is set")
	}
}

func TestInit_WithLimiter(t *testing.T) {
	rh := NewHandler(
		handler.LoggerOption(&testLogger{}),
		handler.TrafficLimiterOption(&mockTrafficLimiter{}),
	).(*routerHandler)

	if err := rh.Init(testMD(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if rh.limiter == nil {
		t.Error("limiter should be non-nil when limiter is set")
	}
}

// ---------------------------------------------------------------------------
// Handle tests
// ---------------------------------------------------------------------------

func TestHandle_BadVersion(t *testing.T) {
	h := newInitdHandler(t)

	// Version2 causes relay.Request.ReadFrom to return an error because the
	// relay protocol only supports Version1. The Handle method returns the
	// read error directly — it never reaches the version check.
	req := relay.Request{
		Version: 0x02,
		Cmd:     relay.CmdAssociate,
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	conn := &fakeConn{buf: buf.Bytes()}
	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error for bad version")
	}

	// Connection must be closed via defer.
	if !conn.closed {
		t.Error("connection was not closed")
	}
}

// TestHandle_BadRequestVersion verifies that Handle rejects requests where
// the version byte has been tampered with. relay.Request.ReadFrom checks the
// version byte before the handler does — the handler's own version check
// (req.Version != relay.Version1) is a defensive secondary guard. Since
// ReadFrom catches bad versions first, Handle returns relay.ErrBadVersion
// from ReadFrom without writing a response.
func TestHandle_BadRequestVersion(t *testing.T) {
	h := newInitdHandler(t)

	// Build a valid relay request with Version1, then override the version byte.
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
		Features: []relay.Feature{
			&relay.TunnelFeature{ID: rid},
			&relay.NetworkFeature{Network: relay.NetworkIP},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	// Override the version byte to something that is not Version1.
	b := buf.Bytes()
	if len(b) > 0 {
		b[0] = 0x02
	}

	conn := &fakeConn{buf: b}
	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error for bad request version")
	}

	// Connection must be closed via defer.
	if !conn.closed {
		t.Error("connection was not closed")
	}
}

func TestHandle_UnknownCmd(t *testing.T) {
	h := newInitdHandler(t)

	req := relay.Request{
		Version: relay.Version1,
		Cmd:     0xFF,
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	conn := &fakeConn{buf: buf.Bytes()}
	err := h.Handle(context.Background(), conn)
	if err != ErrUnknownCmd {
		t.Errorf("err = %v, want ErrUnknownCmd", err)
	}

	resp := readRelayResponse(t, conn.writeBuf.Bytes())
	if resp.Status != relay.StatusBadRequest {
		t.Errorf("status = %d, want BadRequest", resp.Status)
	}
}

func TestHandle_AuthSuccess(t *testing.T) {
	h := newInitdHandler(t,
		handler.AutherOption(&mockAuther{
			authenticateFn: func(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
				return "client-1", true
			},
		}),
	)

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
		Features: []relay.Feature{
			&relay.UserAuthFeature{Username: "user", Password: "pass"},
			&relay.TunnelFeature{ID: rid},
			&relay.NetworkFeature{Network: relay.NetworkIP},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	conn := &fakeConn{buf: buf.Bytes()}
	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestHandle_AuthFailure(t *testing.T) {
	h := newInitdHandler(t,
		handler.AutherOption(&mockAuther{
			authenticateFn: func(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
				return "", false
			},
		}),
	)

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
		Features: []relay.Feature{
			&relay.UserAuthFeature{Username: "user", Password: "wrong"},
			&relay.TunnelFeature{ID: rid},
			&relay.NetworkFeature{Network: relay.NetworkIP},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	conn := &fakeConn{buf: buf.Bytes()}
	err := h.Handle(context.Background(), conn)
	if err != ErrUnauthorized {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}

	resp := readRelayResponse(t, conn.writeBuf.Bytes())
	if resp.Status != relay.StatusUnauthorized {
		t.Errorf("status = %d, want Unauthorized", resp.Status)
	}
}

func TestHandle_AssociateValid(t *testing.T) {
	h := newInitdHandler(t)
	h.md.ingress = nil

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	reqData := buildRelayAssociateRequest(t, "10.0.0.1:0", rid, "ip")

	conn := &fakeConn{buf: reqData}
	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------------

func TestClose(t *testing.T) {
	h := newInitdHandler(t)
	h.Close()
	// should not panic
}

func TestClose_Double(t *testing.T) {
	h := newInitdHandler(t)
	h.Close()
	h.Close() // should not panic
}