package dashboard

import (
	"context"
	"testing"
	"time"

	conncore "github.com/go-gost/core/limiter/conn"
	ratecore "github.com/go-gost/core/limiter/rate"
	trafficcore "github.com/go-gost/core/limiter/traffic"
	connimpl "github.com/go-gost/x/limiter/conn"
	rateimpl "github.com/go-gost/x/limiter/rate"
	limiterstats "github.com/go-gost/x/limiter/stats"
	trafficimpl "github.com/go-gost/x/limiter/traffic"
)

// waitForLimiter polls until the limiter's async initial reload has populated
// the requested key.
func waitForLimiter[T any](t *testing.T, fn func() T) T {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if v := fn(); any(v) != nil {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("limiter not ready")
	var zero T
	return zero
}

func TestWrapConnLimiterExposesStats(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)
	limiterstats.Enable(true)
	defer limiterstats.Enable(false)

	lim := connimpl.NewConnLimiter(connimpl.LimitsOption("$$ 1"))
	w := WrapConnLimiter("conn-1", lim)
	entry := waitForLimiter(t, func() conncore.Limiter { return w.Limiter("1.2.3.4") })
	if !entry.Allow(1) {
		t.Fatal("first allow should succeed")
	}
	if entry.Allow(1) {
		t.Fatal("second allow should be denied")
	}
	Flush()

	m := moduleStats(t, Default().Snapshot(), "limiter_conn", "conn-1", "")
	if m.Limiter == nil || m.Limiter.Calls != 2 || m.Limiter.Allowed != 1 || m.Limiter.Denied != 1 {
		t.Fatalf("limiter stats = %+v", m.Limiter)
	}
}

func TestWrapRateLimiterExposesStats(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)
	limiterstats.Enable(true)
	defer limiterstats.Enable(false)

	lim := rateimpl.NewRateLimiter(rateimpl.LimitsOption("$$ 0.1"))
	w := WrapRateLimiter("rate-1", lim)
	entry := waitForLimiter(t, func() ratecore.Limiter { return w.Limiter("1.2.3.4") })
	if !entry.Allow(1) {
		t.Fatal("first allow should succeed")
	}
	if entry.Allow(1) {
		t.Fatal("second allow should be denied")
	}
	Flush()

	m := moduleStats(t, Default().Snapshot(), "limiter_rate", "rate-1", "")
	if m.Limiter == nil || m.Limiter.Calls != 2 || m.Limiter.Allowed != 1 || m.Limiter.Denied != 1 {
		t.Fatalf("limiter stats = %+v", m.Limiter)
	}
}

func TestWrapTrafficLimiterExposesStats(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)
	limiterstats.Enable(true)
	defer limiterstats.Enable(false)

	lim := trafficimpl.NewTrafficLimiter(trafficimpl.LimitsOption("$$ 100B"))
	w := WrapTrafficLimiter("traffic-1", lim)
	entry := waitForLimiter(t, func() trafficcore.Limiter {
		return w.In(context.Background(), "1.2.3.4:1234")
	})
	if entry == nil {
		t.Fatal("expected conn-level In limiter")
	}
	if got := entry.Wait(context.Background(), 100); got != 100 {
		t.Fatalf("Wait = %d, want 100", got)
	}
	Flush()

	m := moduleStats(t, Default().Snapshot(), "limiter_traffic", "traffic-1", "")
	if m.Limiter == nil || m.Limiter.WaitCalls != 1 || m.Limiter.Requested != 100 || m.Limiter.Granted != 100 {
		t.Fatalf("limiter stats = %+v", m.Limiter)
	}
}

type closeRecordingConnLimiter struct {
	conncore.ConnLimiter
	closed bool
}

func (c *closeRecordingConnLimiter) Close() error {
	c.closed = true
	return nil
}

type closeRecordingRateLimiter struct {
	ratecore.RateLimiter
	closed bool
}

func (c *closeRecordingRateLimiter) Close() error {
	c.closed = true
	return nil
}

type closeRecordingTrafficLimiter struct {
	trafficcore.TrafficLimiter
	closed bool
}

func (c *closeRecordingTrafficLimiter) Close() error {
	c.closed = true
	return nil
}

func TestWrapLimiterCloseForwarding(t *testing.T) {
	connInner := &closeRecordingConnLimiter{ConnLimiter: connimpl.NewConnLimiter()}
	if err := WrapConnLimiter("close-conn", connInner).(interface{ Close() error }).Close(); err != nil {
		t.Fatalf("conn Close: %v", err)
	}
	if !connInner.closed {
		t.Fatal("conn Close was not forwarded")
	}

	rateInner := &closeRecordingRateLimiter{RateLimiter: rateimpl.NewRateLimiter()}
	if err := WrapRateLimiter("close-rate", rateInner).(interface{ Close() error }).Close(); err != nil {
		t.Fatalf("rate Close: %v", err)
	}
	if !rateInner.closed {
		t.Fatal("rate Close was not forwarded")
	}

	trafficInner := &closeRecordingTrafficLimiter{TrafficLimiter: trafficimpl.NewTrafficLimiter()}
	if err := WrapTrafficLimiter("close-traffic", trafficInner).(interface{ Close() error }).Close(); err != nil {
		t.Fatalf("traffic Close: %v", err)
	}
	if !trafficInner.closed {
		t.Fatal("traffic Close was not forwarded")
	}
}
