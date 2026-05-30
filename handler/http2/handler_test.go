package http2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	h2, ok := h.(*http2Handler)
	if !ok {
		t.Fatalf("NewHandler returned %T, want *http2Handler", h)
	}
	if h2.options.Logger != nil {
		t.Error("expected nil logger by default")
	}
}

func TestClose(t *testing.T) {
	h := newTestHandler()
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCloseAfterInit(t *testing.T) {
	h := newTestHandler()
	if err := h.Init(testMD(map[string]any{})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.cancel == nil {
		t.Fatal("cancel not set after Init")
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close after Init: %v", err)
	}
}

func TestInit(t *testing.T) {
	h := newTestHandler(handler.ObserverOption(&testObserver{}))
	if err := h.Init(testMD(map[string]any{})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.stats == nil {
		t.Error("stats not set when observer configured")
	}
	if h.cancel == nil {
		t.Error("cancel not set")
	}
	h.Close()
}

func TestInit_Limiter(t *testing.T) {
	h := newTestHandler(handler.TrafficLimiterOption(&stubTrafficLimiter{}))
	if err := h.Init(testMD(map[string]any{})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.limiter == nil {
		t.Error("limiter not set")
	}
	h.Close()
}

func TestObserveStats_NilObserver(t *testing.T) {
	h := newTestHandler()
	// Should return immediately without panicking.
	h.observeStats(context.Background())
}

func TestObserveStats_CancelledContext(t *testing.T) {
	h := newTestHandler()
	h.md.observerPeriod = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.observeStats(ctx)
}

func TestCheckRateLimit(t *testing.T) {
	t.Run("no limiter", func(t *testing.T) {
		h := newTestHandler()
		addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		if !h.checkRateLimit(addr) {
			t.Error("expected true without limiter")
		}
	})

	t.Run("with limiter", func(t *testing.T) {
		h := newTestHandler(handler.RateLimiterOption(newStubRateLimiter()))
		addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		if !h.checkRateLimit(addr) {
			t.Error("expected true with always-allow limiter")
		}
	})
}

func TestHandle_WrongConnType(t *testing.T) {
	h := newTestHandler()
	if err := h.Init(testMD(map[string]any{})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	err := h.Handle(context.Background(), server)
	if err != ErrWrongConnType {
		t.Errorf("err = %v, want ErrWrongConnType", err)
	}
}
