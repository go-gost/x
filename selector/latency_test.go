package selector

import (
	"context"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
)

// mockProbeReader implements chain.ProbeResultReader.
type mockProbeReader struct {
	result *chain.ProbeResult
}

func (m *mockProbeReader) ProbeResult() *chain.ProbeResult { return m.result }

func TestLowestLatencyStrategy(t *testing.T) {
	strategy := LowestLatencyStrategy[*mockProbeReader]()
	ctx := context.Background()

	fast := &mockProbeReader{result: &chain.ProbeResult{Success: true, Latency: 10 * time.Millisecond}}
	mid := &mockProbeReader{result: &chain.ProbeResult{Success: true, Latency: 50 * time.Millisecond}}
	slow := &mockProbeReader{result: &chain.ProbeResult{Success: true, Latency: 100 * time.Millisecond}}
	fail := &mockProbeReader{result: &chain.ProbeResult{Success: false, Latency: 5 * time.Millisecond}}
	noResult := &mockProbeReader{result: nil}

	// fastest wins
	if got := strategy.Apply(ctx, fast, mid, slow); got != fast {
		t.Error("expected fastest (10ms)")
	}

	// order-independent: fastest wins regardless of position
	if got := strategy.Apply(ctx, slow, mid, fast); got != fast {
		t.Error("expected fastest (10ms) even when last")
	}

	// failed probe deprioritized — picks the successful one
	if got := strategy.Apply(ctx, fail, mid); got != mid {
		t.Error("expected mid (50ms) over failed")
	}

	// nil result deprioritized — picks the one with a result
	if got := strategy.Apply(ctx, noResult, fast); got != fast {
		t.Error("expected fast over nil-result")
	}

	// all failed → fallback to first item (even if failed)
	if got := strategy.Apply(ctx, fail); got != fail {
		t.Error("expected fallback to only item")
	}

	// failed + nil → first encountered wins as fallback
	if got := strategy.Apply(ctx, fail, noResult); got != fail {
		t.Error("expected first fallback item (failed before nil)")
	}
	if got := strategy.Apply(ctx, noResult, fail); got != noResult {
		t.Error("expected first fallback item (nil before failed)")
	}
}

func TestLowestLatencyStrategyOnNodes(t *testing.T) {
	strategy := LowestLatencyStrategy[*chain.Node]()
	ctx := context.Background()

	fast := chain.NewNode("fast", "addr1")
	fast.SetProbeResult(&chain.ProbeResult{Success: true, Latency: 10 * time.Millisecond})

	slow := chain.NewNode("slow", "addr2")
	slow.SetProbeResult(&chain.ProbeResult{Success: true, Latency: 100 * time.Millisecond})

	dead := chain.NewNode("dead", "addr3")
	dead.SetProbeResult(&chain.ProbeResult{Success: false})

	bare := chain.NewNode("bare", "addr4")

	// fastest wins
	if got := strategy.Apply(ctx, fast, slow, dead, bare); got != fast {
		t.Error("expected fast node")
	}

	// only dead + bare → first fallback (dead) wins, even though bare has no result
	if got := strategy.Apply(ctx, dead, bare); got != dead {
		t.Errorf("expected first fallback (dead), got %v", got)
	}

	// only bare + dead → first fallback (bare) wins
	if got := strategy.Apply(ctx, bare, dead); got != bare {
		t.Errorf("expected first fallback (bare), got %v", got)
	}
}

func TestLatencyFilter(t *testing.T) {
	ctx := context.Background()

	filter := LatencyFilter[*mockProbeReader](50 * time.Millisecond)

	ok := &mockProbeReader{result: &chain.ProbeResult{Success: true, Latency: 10 * time.Millisecond}}
	over := &mockProbeReader{result: &chain.ProbeResult{Success: true, Latency: 100 * time.Millisecond}}
	fail := &mockProbeReader{result: &chain.ProbeResult{Success: false, Latency: 1 * time.Millisecond}}
	noResult := &mockProbeReader{result: nil}

	// ok passes, over is filtered
	if got := filter.Filter(ctx, ok, over); len(got) != 1 || got[0] != ok {
		t.Error("expected only ok to pass")
	}

	// single item: len(vs) <= 1 guard keeps it (safety net — don't empty a hop)
	if got := filter.Filter(ctx, fail); len(got) != 1 {
		t.Error("single failed item preserved (len <= 1 guard)")
	}
	if got := filter.Filter(ctx, over); len(got) != 1 {
		t.Error("single over-threshold item preserved (len <= 1 guard)")
	}

	// multi-item: failed is filtered, nil and ok pass through
	if got := filter.Filter(ctx, ok, fail, noResult); len(got) != 2 {
		t.Error("expected 2 pass (ok, noResult)")
	}

	// zero maxLatency is no-op (all pass)
	filter = LatencyFilter[*mockProbeReader](0)
	if got := filter.Filter(ctx, ok, over, fail); len(got) != 3 {
		t.Error("expected all pass through with zero maxLatency")
	}
}

func TestLatencyFilterOnNodes(t *testing.T) {
	filter := LatencyFilter[*chain.Node](50 * time.Millisecond)
	ctx := context.Background()

	ok := chain.NewNode("ok", "addr1")
	ok.SetProbeResult(&chain.ProbeResult{Success: true, Latency: 10 * time.Millisecond})

	over := chain.NewNode("over", "addr2")
	over.SetProbeResult(&chain.ProbeResult{Success: true, Latency: 200 * time.Millisecond})

	dead := chain.NewNode("dead", "addr3")
	dead.SetProbeResult(&chain.ProbeResult{Success: false})

	bare := chain.NewNode("bare", "addr4")

	got := filter.Filter(ctx, ok, over, dead, bare)
	if len(got) != 2 {
		t.Fatalf("expected 2 pass (ok, bare), got %d", len(got))
	}
	names := map[string]bool{}
	for _, n := range got {
		names[n.Name] = true
	}
	if !names["ok"] || !names["bare"] {
		t.Errorf("expected ok and bare, got %v", names)
	}
}
