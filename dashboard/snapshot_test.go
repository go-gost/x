package dashboard

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/observer"
	xstats "github.com/go-gost/x/observer/stats"
)

func TestSnapshotIsDeepCopy(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	_ = c.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "service", Service: "svc", TotalConns: 1},
	})
	snap := c.Snapshot()
	s := snap.Services["svc"]
	s.Stats.TotalConns = 99
	snap.Services["svc"] = s
	if got := c.Snapshot().Services["svc"].Stats.TotalConns; got != 1 {
		t.Fatalf("Snapshot aliased internal state: got %d", got)
	}
}

func TestSnapshotJSONHasStableKeys(t *testing.T) {
	c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
	b, err := json.Marshal(c.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"version"`, `"services"`, `"modules"`, `"chains"`, `"events"`, `"history"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("missing %s in %s", key, b)
		}
	}
}

func TestSnapshotRatesFromHistory(t *testing.T) {
	now := time.Unix(100, 0)
	c := NewCollector(
		HistoryOption(time.Second, 10),
		ClockOption(func() time.Time { return now }),
	)
	observe := func(input uint64) {
		_ = c.Observe(context.Background(), []observer.Event{
			xstats.StatsEvent{
				Kind:        "service",
				Service:     "svc",
				InputBytes:  input,
				OutputBytes: input * 2,
			},
		})
	}

	observe(100)
	now = now.Add(10 * time.Second)
	observe(300)
	now = now.Add(10 * time.Second)
	observe(500)

	got := c.Snapshot().Services["svc"].Rate
	if math.Abs(got.InputBytesPerSecond-20) > 1e-9 {
		t.Fatalf("input rate = %v, want 20", got.InputBytesPerSecond)
	}
	if math.Abs(got.OutputBytesPerSecond-40) > 1e-9 {
		t.Fatalf("output rate = %v, want 40", got.OutputBytesPerSecond)
	}
}
