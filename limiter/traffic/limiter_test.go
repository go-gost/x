package traffic

import (
	"context"
	"testing"

	limiter "github.com/go-gost/core/limiter/traffic"
)

func TestNewLimiter(t *testing.T) {
	l := NewLimiter(100)
	if l == nil {
		t.Fatal("NewLimiter should not be nil")
	}
	if l.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", l.Limit())
	}
}

func TestNewLimiterWithBurst(t *testing.T) {
	l := NewLimiterWithBurst(100, 500)
	if l == nil {
		t.Fatal("NewLimiterWithBurst should not be nil")
	}
	if l.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", l.Limit())
	}
	// With burst=500, Wait for 500 should succeed immediately.
	if n := l.Wait(context.Background(), 500); n != 500 {
		t.Fatalf("expected 500 with burst, got %d", n)
	}
	// With burst=500, Wait for 501 clamps to burst.
	if n := l.Wait(context.Background(), 501); n != 500 {
		t.Fatalf("expected burst 500, got %d", n)
	}
}

func TestNewLimiterWithBurst_Defaults(t *testing.T) {
	// burst <= 0 defaults to rate.
	l := NewLimiterWithBurst(100, 0)
	if l.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", l.Limit())
	}
	if n := l.Wait(context.Background(), 100); n != 100 {
		t.Fatalf("expected burst=rate=100, got %d", n)
	}

	l2 := NewLimiterWithBurst(50, -1)
	if n := l2.Wait(context.Background(), 50); n != 50 {
		t.Fatalf("expected burst=rate=50, got %d", n)
	}
}

func TestLimiter_Wait(t *testing.T) {
	// High burst so Wait does not block.
	l := NewLimiter(1000000)
	n := l.Wait(context.Background(), 3)
	if n != 3 {
		t.Fatalf("expected 3, got %d", n)
	}
}

func TestLimiter_Wait_BurstClamped(t *testing.T) {
	// Burst is 5, request 100 -> clamped to burst.
	l := NewLimiter(5)
	n := l.Wait(context.Background(), 100)
	if n != 5 {
		t.Fatalf("expected burst 5, got %d", n)
	}
}

func TestLimiter_Wait_ContextCancelled(t *testing.T) {
	l := NewLimiter(1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := l.Wait(ctx, 10)
	if n != 0 {
		t.Fatalf("cancelled context should return 0, got %d", n)
	}
}

func TestLimiter_Set(t *testing.T) {
	l := NewLimiter(5)
	l.Set(10)
	if l.Limit() != 10 {
		t.Fatalf("expected limit 10 after Set, got %d", l.Limit())
	}
	// Verify burst also updated: Wait should allow up to 10.
	n := l.Wait(context.Background(), 10)
	if n != 10 {
		t.Fatalf("expected burst 10 after Set, got %d", n)
	}
}

func TestLimiter_String(t *testing.T) {
	l := NewLimiter(42)
	// llimiter implements fmt.Stringer (not part of core interface).
	if s := l.(*llimiter).String(); s != "42" {
		t.Fatalf("expected '42', got '%s'", s)
	}
}

func TestLimiterGroup_SortedByLimit(t *testing.T) {
	g := newLimiterGroup(
		NewLimiter(200),
		NewLimiter(50),
		NewLimiter(100),
	)
	if g.Limit() != 50 {
		t.Fatalf("expected smallest limit 50, got %d", g.Limit())
	}
}

func TestLimiterGroup_Wait(t *testing.T) {
	// Group: [3, 100000] — smallest limit is 3.
	small := NewLimiter(3)
	large := NewLimiter(100000)
	g := newLimiterGroup(large, small)

	// Wait for 3: small returns 3, large returns 3, min = 3.
	n := g.Wait(context.Background(), 3)
	if n != 3 {
		t.Fatalf("expected 3, got %d", n)
	}

	// Wait for 5: small clamps to burst=3, returns 3, large returns 5, min = 3.
	n = g.Wait(context.Background(), 5)
	if n != 3 {
		t.Fatalf("expected min=3, got %d", n)
	}
}

func TestLimiterGroup_Limit(t *testing.T) {
	g := newLimiterGroup(NewLimiter(10), NewLimiter(5), NewLimiter(20))
	if g.Limit() != 5 {
		t.Fatalf("expected 5, got %d", g.Limit())
	}
}

func TestLimiterGroup_Set(t *testing.T) {
	g := newLimiterGroup(NewLimiter(5))
	g.Set(100)
	if g.Limit() != 5 {
		t.Fatal("Set should be a no-op on limiterGroup")
	}
}

func TestLimiterGroup_Empty(t *testing.T) {
	g := newLimiterGroup()
	if g.Limit() != 0 {
		t.Fatalf("empty group limit should be 0, got %d", g.Limit())
	}
	n := g.Wait(context.Background(), 100)
	if n != 100 {
		t.Fatalf("empty group Wait should return n unchanged, got %d", n)
	}
}

func TestLimiterGroup_String(t *testing.T) {
	g := newLimiterGroup(NewLimiter(5))
	if g.String() != "[5]" {
		t.Fatalf("expected '[5]', got '%s'", g.String())
	}
}

var (
	_ limiter.Limiter = (*llimiter)(nil)
	_ limiter.Limiter = (*limiterGroup)(nil)
)
