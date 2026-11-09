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

func TestCollectorHandlerClientLimitEvictsOldest(t *testing.T) {
	now := time.Unix(100, 0)
	c := NewCollector(
		ClientLimitOption(2),
		ClockOption(func() time.Time { return now }),
	)
	observe := func(client string, input uint64) {
		_ = c.Observe(context.Background(), []observer.Event{
			xstats.StatsEvent{Kind: "handler", Service: "svc", Client: client, InputBytes: input},
		})
	}

	observe("a", 1)
	now = now.Add(time.Second)
	observe("b", 2)
	now = now.Add(time.Second)
	observe("c", 4)

	if got := c.Snapshot().Services["svc"].Stats.InputBytes; got != 6 {
		t.Fatalf("input bytes = %d, want 6 (oldest client evicted)", got)
	}
}

func TestCollectorModuleErrorSeqIsIdempotent(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	ev := ModuleErrorEvent{Kind: "admission", Name: "lan", Service: "svc", Message: "denied", Seq: 1}
	_ = c.Observe(context.Background(), []observer.Event{ev})
	_ = c.Observe(context.Background(), []observer.Event{ev})

	snap := c.Snapshot()
	if len(snap.Events) != 1 {
		t.Fatalf("events = %d, want 1 after retry", len(snap.Events))
	}
	if len(snap.Modules) != 1 || snap.Modules[0].Stats.Errors != 1 {
		t.Fatalf("module errors = %+v, want 1", snap.Modules)
	}
}

func TestCollectorErrorEventDoesNotDoubleCountCumulativeStats(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		ModuleStatsEvent{Kind: "resolver", Name: "local", Errors: 1},
		ModuleErrorEvent{Kind: "resolver", Name: "local", Message: "resolver error", Seq: 1},
	})

	snap := c.Snapshot()
	if len(snap.Modules) != 1 || snap.Modules[0].Stats.Errors != 1 {
		t.Fatalf("module errors = %+v, want 1", snap.Modules)
	}
}

func TestCollectorResetClearsServiceSeenLatch(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "service", Service: "svc", InputBytes: 1000},
	})

	c.Reset()

	_ = c.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.1", InputBytes: 7},
	})
	if got := c.Snapshot().Services["svc"].Stats.InputBytes; got != 7 {
		t.Fatalf("input bytes = %d, want 7 after reset", got)
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

func TestObserveChainsFiltersByAllowedNames(t *testing.T) {
	c := NewCollector()
	c.SetChainFilter(map[string]struct{}{"chain-0": {}})
	c.ObserveChains(map[string]*ChainSnapshot{
		"chain-0":   {Name: "chain-0"},
		"chain-old": {Name: "chain-old"},
	})
	snap := c.Snapshot()
	if _, ok := snap.Chains["chain-0"]; !ok {
		t.Fatal("chain-0 should be present")
	}
	if _, ok := snap.Chains["chain-old"]; ok {
		t.Fatal("chain-old should be filtered out")
	}
}
