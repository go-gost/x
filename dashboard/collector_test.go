package dashboard

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/observer"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/go-gost/x/service"
)

type unknownEvent struct{}

func (unknownEvent) Type() observer.EventType { return "unknown" }

func TestCollectorStatsEventReplacesCumulativeSnapshot(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "service", Service: "svc", TotalConns: 10, InputBytes: 100},
		xstats.StatsEvent{Kind: "service", Service: "svc", TotalConns: 10, InputBytes: 100},
	})
	got := c.Snapshot().Services["svc"]
	if got.Stats.TotalConns != 10 || got.Stats.InputBytes != 100 {
		t.Fatalf("duplicate batch double-counted: %+v", got.Stats)
	}
}

func TestCollectorServiceStateEvent(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "svc", State: service.StateReady},
	})
	if got := c.Snapshot().Services["svc"].State; got != "ready" {
		t.Fatalf("state = %q, want ready", got)
	}
}

func TestCollectorModuleStatsUsesKey(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		ModuleStatsEvent{Kind: "bypass", Name: "direct", Service: "svc", Calls: 7, Hits: 5},
	})
	s := c.Snapshot()
	if len(s.Modules) != 1 || s.Modules[0].Stats.Calls != 7 || s.Modules[0].Stats.Hits != 5 {
		t.Fatalf("modules = %+v", s.Modules)
	}
}

func TestCollectorObserveAlwaysReturnsNilAndIgnoresUnknown(t *testing.T) {
	c := NewCollector()
	if err := c.Observe(context.Background(), []observer.Event{unknownEvent{}}); err != nil {
		t.Fatalf("Observe returned %v", err)
	}
}

func TestCollectorEventRingIsBounded(t *testing.T) {
	c := NewCollector(EventLimitOption(2), ClockOption(func() time.Time { return time.Unix(100, 0) }))
	for i := 0; i < 5; i++ {
		_ = c.Observe(context.Background(), []observer.Event{
			ModuleErrorEvent{Kind: "admission", Name: "lan", Service: "svc", Message: "denied"},
		})
	}
	if got := len(c.Snapshot().Events); got != 2 {
		t.Fatalf("events = %d, want 2", got)
	}
}

func TestCollectorHandlerStatsSumAcrossClients(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.1", InputBytes: 100},
		xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.2", InputBytes: 200},
	})
	got := c.Snapshot().Services["svc"].Stats.InputBytes
	if got != 300 {
		t.Fatalf("input bytes = %d, want 300", got)
	}
}

func TestCollectorHandlerStatsRetryIsIdempotent(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	ev := xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.1", InputBytes: 100}
	_ = c.Observe(context.Background(), []observer.Event{ev})
	_ = c.Observe(context.Background(), []observer.Event{ev})
	if got := c.Snapshot().Services["svc"].Stats.InputBytes; got != 100 {
		t.Fatalf("retry double-counted: %d", got)
	}
}

func TestCollectorConcurrentObserveAndSnapshot(t *testing.T) {
	c := NewCollector()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = c.Observe(context.Background(), []observer.Event{
				xstats.StatsEvent{Kind: "handler", Service: "svc", Client: fmt.Sprintf("10.0.0.%d", i), InputBytes: uint64(i)},
			})
		}(i)
		go func() {
			defer wg.Done()
			_ = c.Snapshot()
		}()
	}
	wg.Wait()
}
