package limiter

import (
	"context"
	"testing"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
)

// --- mock types ---

type mockLimiter struct {
	limit int
}

func (m *mockLimiter) Wait(ctx context.Context, n int) int { return n }
func (m *mockLimiter) Limit() int                          { return m.limit }
func (m *mockLimiter) Set(n int)                           { m.limit = n }

type mockTrafficLimiter struct {
	inCalls  int
	outCalls int
	inLim    traffic.Limiter
	outLim   traffic.Limiter
}

func (m *mockTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	m.inCalls++
	return m.inLim
}

func (m *mockTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	m.outCalls++
	return m.outLim
}

// --- tests ---

func TestCachedTrafficLimiter_In(t *testing.T) {
	inner := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	cached := NewCachedTrafficLimiter(inner, RefreshIntervalOption(50*time.Millisecond))
	if cached == nil {
		t.Fatal("NewCachedTrafficLimiter should not return nil")
	}

	ctx := context.Background()
	v1 := cached.In(ctx, "key1")
	if v1 == nil {
		t.Fatal("first In() should return a limiter")
	}
	if v1.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", v1.Limit())
	}
	if inner.inCalls != 1 {
		t.Fatalf("expected 1 In call, got %d", inner.inCalls)
	}

	// Second call: should return cached result without calling inner again.
	v2 := cached.In(ctx, "key1")
	if v2 == nil {
		t.Fatal("cached In() should return a limiter")
	}
	if inner.inCalls != 1 {
		t.Fatalf("cached call should not invoke inner, got %d calls", inner.inCalls)
	}
}

func TestCachedTrafficLimiter_Out(t *testing.T) {
	inner := &mockTrafficLimiter{outLim: &mockLimiter{limit: 200}}
	cached := NewCachedTrafficLimiter(inner, RefreshIntervalOption(50*time.Millisecond))

	ctx := context.Background()
	v1 := cached.Out(ctx, "key1")
	if v1 == nil {
		t.Fatal("first Out() should return a limiter")
	}
	if v1.Limit() != 200 {
		t.Fatalf("expected limit 200, got %d", v1.Limit())
	}
	if inner.outCalls != 1 {
		t.Fatalf("expected 1 Out call, got %d", inner.outCalls)
	}

	cached.Out(ctx, "key1")
	if inner.outCalls != 1 {
		t.Fatalf("cached call should not invoke inner, got %d calls", inner.outCalls)
	}
}

func TestCachedTrafficLimiter_Expiration(t *testing.T) {
	inner := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	// Bypass constructor to avoid 1s minimum refresh interval.
	cached := NewCachedTrafficLimiter(inner, RefreshIntervalOption(10*time.Millisecond))
	if cached == nil {
		t.Fatal("NewCachedTrafficLimiter should not return nil")
	}
	ct := cached.(*cachedTrafficLimiter)
	ct.options.refreshInterval = 10 * time.Millisecond

	ctx := context.Background()
	ct.In(ctx, "key1")
	if inner.inCalls != 1 {
		t.Fatalf("expected 1 In call, got %d", inner.inCalls)
	}

	// Wait for cache to expire.
	time.Sleep(30 * time.Millisecond)

	ct.In(ctx, "key1")
	if inner.inCalls != 2 {
		t.Fatalf("after expiration, inner In should be called again, got %d calls", inner.inCalls)
	}
}

func TestCachedTrafficLimiter_ScopeFilter(t *testing.T) {
	inner := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	cached := NewCachedTrafficLimiter(inner,
		RefreshIntervalOption(50*time.Millisecond),
		ScopeOption("service"),
	)

	ctx := context.Background()

	// Non-matching scope: returns nil.
	v := cached.In(ctx, "key1", limiter.ScopeOption(limiter.ScopeConn))
	if v != nil {
		t.Fatal("non-matching scope should return nil")
	}

	// Matching scope: returns limiter.
	v = cached.In(ctx, "key1", limiter.ScopeOption(limiter.ScopeService))
	if v == nil {
		t.Fatal("matching scope should return limiter")
	}
}

func TestCachedTrafficLimiter_NilInner(t *testing.T) {
	cached := NewCachedTrafficLimiter(nil)
	if cached != nil {
		t.Fatal("NewCachedTrafficLimiter(nil) should return nil")
	}
}

func TestCachedTrafficLimiter_NilNew(t *testing.T) {
	inner := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	cached := NewCachedTrafficLimiter(inner, RefreshIntervalOption(10*time.Millisecond))
	if cached == nil {
		t.Fatal("NewCachedTrafficLimiter should not return nil")
	}
	ct := cached.(*cachedTrafficLimiter)
	ct.options.refreshInterval = 10 * time.Millisecond

	ctx := context.Background()
	v1 := ct.In(ctx, "key1")
	if v1 == nil || v1.Limit() != 100 {
		t.Fatal("first In() should return limiter with limit 100")
	}

	// Now make inner return nil.
	inner.inLim = nil

	// Wait for cache to expire.
	time.Sleep(30 * time.Millisecond)

	// After expiration: inner returns nil, falls back to cached limiter.
	v2 := ct.In(ctx, "key1")
	if v2 == nil {
		t.Fatal("should fall back to cached limiter when inner returns nil")
	}
	if v2.Limit() != 100 {
		t.Fatalf("expected fallback limit 100, got %d", v2.Limit())
	}
}
