package dashboard

import (
	"testing"

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

	chainName, nodeName := "test-collect-chain", "test-collect-node"
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
