package dashboard

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-gost/core/metrics"
	xmetrics "github.com/go-gost/x/metrics"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

func label(name, value string) *dto.LabelPair {
	return &dto.LabelPair{Name: proto.String(name), Value: proto.String(value)}
}

func TestCollectChainStatsFromMetrics(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	orig := chainGatherer
	defer func() { chainGatherer = orig }()

	chainGatherer = func() ([]*dto.MetricFamily, error) {
		return []*dto.MetricFamily{
			{
				Name: proto.String("gost_chain_errors_total"),
				Type: dto.MetricType_COUNTER.Enum(),
				Metric: []*dto.Metric{{
					Label: []*dto.LabelPair{
						label("host", "h"),
						label("chain", "chain-0"),
						label("node", "node-0"),
					},
					Counter: &dto.Counter{Value: proto.Float64(2)},
				}},
			},
			{
				Name: proto.String("gost_chain_node_connect_duration_seconds"),
				Type: dto.MetricType_HISTOGRAM.Enum(),
				Metric: []*dto.Metric{{
					Label: []*dto.LabelPair{
						label("host", "h"),
						label("chain", "chain-0"),
						label("node", "node-0"),
					},
					Histogram: &dto.Histogram{SampleCount: proto.Uint64(3), SampleSum: proto.Float64(0.006)},
				}},
			},
		}, nil
	}

	Flush()
	snap := Default().Snapshot()
	cs, ok := snap.Chains["chain-0"]
	if !ok {
		t.Fatal("chain not found")
	}
	if cs.Stats.Errors != 2 || cs.Stats.ConnectCount != 3 || cs.Stats.Connects != 3 {
		t.Fatalf("chain stats = %+v", cs.Stats)
	}
	if cs.Stats.ConnectDurationSumMicros != 6000 {
		t.Fatalf("duration micros = %d, want 6000", cs.Stats.ConnectDurationSumMicros)
	}
	if len(cs.Nodes) != 1 || cs.Nodes[0].Name != "node-0" || cs.Nodes[0].Stats.Errors != 2 {
		t.Fatalf("nodes = %+v", cs.Nodes)
	}
}

func TestCollectChainStatsIgnoresUnknownMetrics(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	orig := chainGatherer
	defer func() { chainGatherer = orig }()
	chainGatherer = func() ([]*dto.MetricFamily, error) { return nil, nil }

	if got := CollectChainStats(); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

func TestCollectChainStatsReadsPrometheusRegistry(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	origEnabled := xmetrics.IsEnabled()
	xmetrics.Enable(true)
	defer xmetrics.Enable(origEnabled)

	// Use a unique name so repeated runs (-count=2) do not assert against
	// counters left behind by a previous run.
	chainName := fmt.Sprintf("test-collect-chain-%d", time.Now().UnixNano())
	nodeName := "test-collect-node"
	if v := xmetrics.GetCounter(xmetrics.MetricChainErrorsCounter,
		metrics.Labels{"chain": chainName, "node": nodeName}); v != nil {
		v.Inc()
	}
	if v := xmetrics.GetObserver(xmetrics.MetricNodeConnectDurationObserver,
		metrics.Labels{"chain": chainName, "node": nodeName}); v != nil {
		v.Observe(0.002)
	}

	Flush()
	cs, ok := Default().Snapshot().Chains[chainName]
	if !ok || cs.Stats.Errors != 1 || cs.Stats.ConnectCount != 1 {
		t.Fatalf("chain stats = %+v", cs)
	}
}

func TestCollectChainStatsSkipsMalformedMetrics(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	orig := chainGatherer
	defer func() { chainGatherer = orig }()
	chainGatherer = func() ([]*dto.MetricFamily, error) {
		return []*dto.MetricFamily{
			{
				Name: proto.String("gost_chain_errors_total"),
				Type: dto.MetricType_COUNTER.Enum(),
				Metric: []*dto.Metric{
					{Label: []*dto.LabelPair{label("chain", "chain-0")}, Counter: &dto.Counter{Value: proto.Float64(1)}},
					{Label: []*dto.LabelPair{label("node", "node-0")}, Counter: &dto.Counter{Value: proto.Float64(1)}},
					{Label: []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-0")}},
				},
			},
			{
				Name: proto.String("gost_chain_node_connect_duration_seconds"),
				Type: dto.MetricType_HISTOGRAM.Enum(),
				Metric: []*dto.Metric{
					{Label: []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-0")}},
				},
			},
			{
				Name: proto.String("gost_unknown_metric"),
				Type: dto.MetricType_COUNTER.Enum(),
				Metric: []*dto.Metric{{
					Label:   []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-0")},
					Counter: &dto.Counter{Value: proto.Float64(1)},
				}},
			},
		}, nil
	}

	cs := CollectChainStats()["chain-0"]
	if cs == nil {
		t.Fatal("chain not found")
	}
	if cs.Stats.Errors != 0 || cs.Stats.ConnectCount != 0 {
		t.Fatalf("malformed metrics produced stats: %+v", cs.Stats)
	}
}

func TestCollectChainStatsAggregatesNodes(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	orig := chainGatherer
	defer func() { chainGatherer = orig }()
	chainGatherer = func() ([]*dto.MetricFamily, error) {
		return []*dto.MetricFamily{
			{
				Name: proto.String("gost_chain_errors_total"),
				Type: dto.MetricType_COUNTER.Enum(),
				Metric: []*dto.Metric{
					{Label: []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-0")}, Counter: &dto.Counter{Value: proto.Float64(2)}},
					{Label: []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-1")}, Counter: &dto.Counter{Value: proto.Float64(3)}},
				},
			},
			{
				Name: proto.String("gost_chain_node_connect_duration_seconds"),
				Type: dto.MetricType_HISTOGRAM.Enum(),
				Metric: []*dto.Metric{
					{Label: []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-0")}, Histogram: &dto.Histogram{SampleCount: proto.Uint64(2), SampleSum: proto.Float64(0.004)}},
					{Label: []*dto.LabelPair{label("chain", "chain-0"), label("node", "node-1")}, Histogram: &dto.Histogram{SampleCount: proto.Uint64(1), SampleSum: proto.Float64(0.001)}},
				},
			},
		}, nil
	}

	cs := CollectChainStats()["chain-0"]
	if cs == nil {
		t.Fatal("chain not found")
	}
	if cs.Stats.Errors != 5 || cs.Stats.ConnectCount != 3 || cs.Stats.Connects != 3 {
		t.Fatalf("chain stats = %+v", cs.Stats)
	}
	if cs.Stats.ConnectDurationSumMicros != 5000 {
		t.Fatalf("duration micros = %d, want 5000", cs.Stats.ConnectDurationSumMicros)
	}
	if len(cs.Nodes) != 2 {
		t.Fatalf("nodes = %+v", cs.Nodes)
	}
	for _, n := range cs.Nodes {
		switch n.Name {
		case "node-0":
			if n.Stats.Errors != 2 || n.Stats.ConnectCount != 2 || n.Stats.ConnectDurationSumMicros != 4000 {
				t.Fatalf("node-0 stats = %+v", n.Stats)
			}
		case "node-1":
			if n.Stats.Errors != 3 || n.Stats.ConnectCount != 1 || n.Stats.ConnectDurationSumMicros != 1000 {
				t.Fatalf("node-1 stats = %+v", n.Stats)
			}
		default:
			t.Fatalf("unexpected node %q", n.Name)
		}
	}
}

func TestObserveChainsReplacesAndClears(t *testing.T) {
	c := NewCollector()
	c.ObserveChains(map[string]*ChainSnapshot{"a": {Name: "a", Stats: ChainStats{Errors: 1}}})
	if len(c.Snapshot().Chains) != 1 {
		t.Fatalf("chains = %+v", c.Snapshot().Chains)
	}
	c.ObserveChains(map[string]*ChainSnapshot{"b": {Name: "b"}})
	if _, ok := c.Snapshot().Chains["a"]; ok {
		t.Fatalf("old chain still present: %+v", c.Snapshot().Chains)
	}
	if _, ok := c.Snapshot().Chains["b"]; !ok {
		t.Fatalf("new chain missing: %+v", c.Snapshot().Chains)
	}
	c.ObserveChains(nil)
	if len(c.Snapshot().Chains) != 0 {
		t.Fatalf("empty observe did not clear chains: %+v", c.Snapshot().Chains)
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

func TestFlushClearsChainsWhenMetricsDisabled(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	origEnabled := xmetrics.IsEnabled()
	xmetrics.Enable(false)
	defer xmetrics.Enable(origEnabled)

	Default().ObserveChains(map[string]*ChainSnapshot{"stale": {Name: "stale"}})
	Flush()
	if got := len(Default().Snapshot().Chains); got != 0 {
		t.Fatalf("chains = %d, want 0", got)
	}
}
