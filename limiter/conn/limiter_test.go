package conn

import (
	"sync"
	"sync/atomic"
	"testing"

	limiter "github.com/go-gost/core/limiter/conn"
)

func TestLimiter_Allow(t *testing.T) {
	l := NewLimiter(3).(*llimiter)

	if l.Limit() != 3 {
		t.Fatalf("expected limit 3, got %d", l.Limit())
	}

	// Basic acquire/release within limit.
	for i := 0; i < 3; i++ {
		if !l.Allow(1) {
			t.Fatalf("Allow(1) #%d should succeed", i)
		}
	}
	if l.Allow(1) {
		t.Fatal("Allow(1) should fail after reaching limit")
	}

	// Release one and re-acquire.
	if !l.Allow(-1) {
		t.Fatal("Allow(-1) should always succeed")
	}
	if !l.Allow(1) {
		t.Fatal("Allow(1) should succeed after release")
	}
}

func TestLimiter_AllowZero(t *testing.T) {
	l := NewLimiter(1)
	if !l.Allow(0) {
		t.Fatal("Allow(0) should not fail with no connections")
	}
}

func TestLimiter_AllowNegative(t *testing.T) {
	l := NewLimiter(1)
	// Allow(-1) should always return true even without prior acquire.
	if !l.Allow(-1) {
		t.Fatal("Allow(-1) should succeed")
	}
	// Allow(-1) again — still succeeds.
	if !l.Allow(-1) {
		t.Fatal("Allow(-1) should succeed again")
	}
}

func TestLimiter_Concurrent(t *testing.T) {
	l := NewLimiter(100)
	var wg sync.WaitGroup
	n := 200
	var success int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow(1) {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()
	if v := atomic.LoadInt64(&success); v != 100 {
		t.Errorf("expected 100 successes, got %d", v)
	}
}

func TestLimiterGroup_Allow(t *testing.T) {
	lg := newLimiterGroup(NewLimiter(2), NewLimiter(5), NewLimiter(10))

	if lg.Limit() != 2 {
		t.Fatalf("expected group limit 2 (smallest), got %d", lg.Limit())
	}

	// Each Allow must pass all limiters.
	for i := 0; i < 2; i++ {
		if !lg.Allow(1) {
			t.Fatalf("lg.Allow(1) #%d should succeed", i)
		}
	}
	if lg.Allow(1) {
		t.Fatal("lg.Allow(1) should fail after 2 connections (tightest limit=2)")
	}
}

func TestLimiterGroup_AllowRelease(t *testing.T) {
	lg := newLimiterGroup(NewLimiter(1), NewLimiter(10))

	if !lg.Allow(1) {
		t.Fatal("Allow(1) should succeed")
	}
	if lg.Allow(1) {
		t.Fatal("Allow(1) should fail")
	}

	// Release on group must propagate to all limiters.
	if !lg.Allow(-1) {
		t.Fatal("Allow(-1) should succeed")
	}

	// Should be able to acquire again.
	if !lg.Allow(1) {
		t.Fatal("Allow(1) should succeed after release")
	}
}

func TestLimiterGroup_AllowRollback(t *testing.T) {
	// limiters sorted: [1, 5] (ascending by limit).
	lg := newLimiterGroup(NewLimiter(5), NewLimiter(1))

	// First Allow passes both limiters.
	if !lg.Allow(1) {
		t.Fatal("first Allow(1) should succeed")
	}

	// Second Allow fails on the tightest limiter (limit=1) and rolls back.
	if lg.Allow(1) {
		t.Fatal("second Allow(1) should fail after limit reached")
	}

	// The tightest limiter should still be at 1 (rollback worked).
	ll := lg.limiters[0].(*llimiter)
	if ll.current != 1 {
		t.Errorf("first limiter should be at 1 after rollback, got %d", ll.current)
	}
}

func TestLimiterGroup_BadInput(t *testing.T) {
	lg := newLimiterGroup(NewLimiter(-5), NewLimiter(10))
	if lg.Limit() != -5 {
		t.Fatalf("expected limit -5 for negative-limit limiter")
	}
}

func TestLimiterGroup_Empty(t *testing.T) {
	lg := newLimiterGroup()
	if lg.Limit() != 0 {
		t.Fatal("empty group limit should be 0")
	}
	// Empty group returns false (no limiters to consult).
	if lg.Allow(1) {
		t.Fatal("Allow(1) on empty group should return false")
	}
}

var _ limiter.Limiter = (*llimiter)(nil)
var _ limiter.Limiter = (*limiterGroup)(nil)
