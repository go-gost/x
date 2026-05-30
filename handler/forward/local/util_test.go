package local

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/limiter/rate"
	xctx "github.com/go-gost/x/ctx"
)

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

func TestNewRecorderObject_UDP(t *testing.T) {
	h := newInitdHandler()
	conn := &packetConn{newStringConn(nil)}

	ro := h.newRecorderObject(context.Background(), conn, time.Now())

	if ro.Network != "udp" {
		t.Errorf("expected network udp, got %s", ro.Network)
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
// checkRateLimit
// ---------------------------------------------------------------------------

func TestCheckRateLimit_NilLimiter(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)

	if !h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected true when RateLimiter is nil")
	}
}

func TestCheckRateLimit_NilAddr(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&stubRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &stubLimiter{allowFn: func(n int) bool { return false }}
		},
	}))

	if !h.checkRateLimit(nil) {
		t.Error("expected true when addr is nil")
	}
}

func TestCheckRateLimit_Allowed(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&stubRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &stubLimiter{allowFn: func(n int) bool { return true }}
		},
	}))
	conn := newStringConn(nil)

	if !h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected true when limiter allows")
	}
}

func TestCheckRateLimit_Blocked(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&stubRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &stubLimiter{allowFn: func(n int) bool { return false }}
		},
	}))
	conn := newStringConn(nil)

	if h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected false when limiter blocks")
	}
}

func TestCheckRateLimit_NoLimiterForKey(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&stubRateLimiter{
		limiterFn: func(key string) rate.Limiter { return nil },
	}))
	conn := newStringConn(nil)

	if !h.checkRateLimit(conn.RemoteAddr()) {
		t.Error("expected true when no limiter found for key")
	}
}
