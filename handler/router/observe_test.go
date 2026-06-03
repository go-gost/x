package router

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
	stats_util "github.com/go-gost/x/internal/util/stats"
)

// ---------------------------------------------------------------------------
// checkRateLimit tests
// ---------------------------------------------------------------------------

func TestCheckRateLimit_NilLimiter(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			RateLimiter: nil,
		},
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("checkRateLimit returned false, want true")
	}
}

func TestCheckRateLimit_Allowed(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			RateLimiter: &mockRateLimiterContainer{
				limiterFn: func(key string) rate.Limiter {
					return &mockRateLimiter{
						allowFn: func(n int) bool { return true },
					}
				},
			},
		},
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("checkRateLimit returned false, want true")
	}
}

func TestCheckRateLimit_Denied(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			RateLimiter: &mockRateLimiterContainer{
				limiterFn: func(key string) rate.Limiter {
					return &mockRateLimiter{
						allowFn: func(n int) bool { return false },
					}
				},
			},
		},
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	if h.checkRateLimit(addr) {
		t.Error("checkRateLimit returned true, want false")
	}
}

func TestCheckRateLimit_LimiterByHost(t *testing.T) {
	var gotKey string
	h := &routerHandler{
		options: handler.Options{
			RateLimiter: &mockRateLimiterContainer{
				limiterFn: func(key string) rate.Limiter {
					gotKey = key
					return &mockRateLimiter{
						allowFn: func(n int) bool { return true },
					}
				},
			},
		},
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	h.checkRateLimit(addr)
	if gotKey != "10.0.0.1" {
		t.Errorf("limiter key = %q, want 10.0.0.1", gotKey)
	}
}

// ---------------------------------------------------------------------------
// observeStats tests
// ---------------------------------------------------------------------------

// newHandlerWithObserver creates a routerHandler with a fake observer.
func newHandlerWithObserver(t *testing.T, obs *fakeObserver) *routerHandler {
	t.Helper()
	h := &routerHandler{
		options: handler.Options{
			Observer: obs,
			Service:  "test-svc",
		},
		md: metadata{
			observerPeriod:       50 * time.Millisecond,
			observerResetTraffic: false,
		},
	}
	h.stats = stats_util.NewHandlerStats("test-svc", false)
	return h
}

func TestObserveStats_NilObserver(t *testing.T) {
	h := &routerHandler{}
	// Should return immediately without panic
	h.observeStats(context.Background())
}

func TestObserveStats_NormalCycle(t *testing.T) {
	obs := newFakeObserver(10)
	h := newHandlerWithObserver(t, obs)

	// Simulate some stat activity so Events() returns data.
	h.stats.Stats("client-1").Add(stats.KindTotalConns, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.observeStats(ctx)
	}()

	// Wait for at least one observation cycle
	select {
	case <-obs.Events():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for observer event")
	}

	cancel()
	wg.Wait()
}

func TestObserveStats_ContextCancel(t *testing.T) {
	obs := newFakeObserver(10)
	h := newHandlerWithObserver(t, obs)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should return immediately when context is already cancelled
	done := make(chan struct{})
	go func() {
		h.observeStats(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observeStats did not exit after context cancel")
	}
}

func TestObserveStats_RetryOnError(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	obs := &fakeObserver{
		eventsCh: make(chan []observer.Event, 10),
		errFunc: func() error {
			mu.Lock()
			callCount++
			count := callCount
			mu.Unlock()
			if count <= 2 {
				return errors.New("observer error")
			}
			return nil
		},
	}
	h := newHandlerWithObserver(t, obs)

	// Simulate stat activity so Events() returns data.
	h.stats.Stats("client-1").Add(stats.KindTotalConns, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.observeStats(ctx)
	}()

	// Wait for successful observation (callCount > 2)
	select {
	case <-obs.Events():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for successful observer event")
	}

	mu.Lock()
	if callCount < 2 {
		t.Errorf("callCount = %d, want at least 2 (error retries)", callCount)
	}
	mu.Unlock()

	cancel()
	wg.Wait()
}