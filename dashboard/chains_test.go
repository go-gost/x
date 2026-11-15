package dashboard

import (
	"errors"
	"testing"
	"time"

	xmetrics "github.com/go-gost/x/metrics"
)

func TestHopRecordsSuccess(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	recordChainHop("chain-0", 0, "node-0", 2*time.Millisecond, nil)

	snap := Default().Snapshot()
	cs, ok := snap.Chains["chain-0"]
	if !ok {
		t.Fatal("chain not found")
	}
	if cs.Stats.Errors != 0 {
		t.Fatalf("errors = %d", cs.Stats.Errors)
	}
	if cs.Stats.Connects != 1 || cs.Stats.ConnectCount != 1 {
		t.Fatalf("stats = %+v", cs.Stats)
	}
	if cs.Stats.ConnectDurationSumMicros != 2000 {
		t.Fatalf("duration micros = %d", cs.Stats.ConnectDurationSumMicros)
	}
	if len(cs.Hops) != 1 || cs.Hops[0].Name != "node-0" {
		t.Fatalf("hops = %+v", cs.Hops)
	}
	if len(cs.Hops[0].Nodes) != 1 || cs.Hops[0].Nodes[0].Stats.Connects != 1 {
		t.Fatalf("hop nodes = %+v", cs.Hops[0].Nodes)
	}
	if len(cs.Nodes) != 1 || cs.Nodes[0].Name != "node-0" {
		t.Fatalf("nodes = %+v", cs.Nodes)
	}
}

func TestHopRecordsFailure(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	recordChainHop("chain-0", 0, "node-0", 0, errors.New("dial"))
	recordChainHop("chain-0", 0, "node-0", time.Millisecond, nil)

	cs, ok := Default().Snapshot().Chains["chain-0"]
	if !ok {
		t.Fatal("chain not found")
	}
	if cs.Stats.Errors != 1 || cs.Stats.Connects != 1 {
		t.Fatalf("stats = %+v", cs.Stats)
	}
	if cs.Stats.ConnectCount != 1 || cs.Stats.ConnectDurationSumMicros != 1000 {
		t.Fatalf("duration fields = %+v", cs.Stats)
	}
	if cs.Hops[0].Nodes[0].Stats.Errors != 1 {
		t.Fatalf("hop node stats = %+v", cs.Hops[0].Nodes[0].Stats)
	}
}

func TestResetClearsChainSeries(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	recordChainHop("chain-0", 0, "node-0", time.Millisecond, nil)
	ResetState()
	if got := len(Default().Snapshot().Chains); got != 0 {
		t.Fatalf("chains after reset = %d", got)
	}
}

func TestChainFilterExcludesUnconfiguredChains(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	recordChainHop("chain-0", 0, "node-0", time.Millisecond, nil)
	recordChainHop("chain-other", 0, "node-1", time.Millisecond, nil)

	Default().SetChainFilter(map[string]struct{}{"chain-0": {}})
	snap := Default().Snapshot()
	if _, ok := snap.Chains["chain-0"]; !ok {
		t.Fatal("chain-0 missing")
	}
	if _, ok := snap.Chains["chain-other"]; ok {
		t.Fatal("chain-other should be filtered out")
	}

	Default().SetChainFilter(nil)
	snap = Default().Snapshot()
	if _, ok := snap.Chains["chain-other"]; !ok {
		t.Fatal("clearing filter should restore chains")
	}
}

func TestSnapshotMetricsEnabled(t *testing.T) {
	c := NewCollector()
	orig := xmetrics.IsEnabled()
	defer xmetrics.Enable(orig)

	xmetrics.Enable(true)
	if !c.Snapshot().MetricsEnabled {
		t.Fatal("MetricsEnabled = false, want true")
	}
	xmetrics.Enable(false)
	if c.Snapshot().MetricsEnabled {
		t.Fatal("MetricsEnabled = true, want false")
	}
}
