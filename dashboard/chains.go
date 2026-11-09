package dashboard

import (
	xmetrics "github.com/go-gost/x/metrics"
	dto "github.com/prometheus/client_model/go"
)

// chainGatherer is a seam so tests can inject synthetic Prometheus families.
var chainGatherer = func() ([]*dto.MetricFamily, error) {
	if !xmetrics.IsEnabled() {
		return nil, nil
	}
	return xmetrics.Registry().Gather()
}

// CollectChainStats reads the chain/node counters already exported to
// Prometheus. Metrics are process-cumulative and survive config reloads.
func CollectChainStats() map[string]*ChainSnapshot {
	mfs, err := chainGatherer()
	if err != nil || len(mfs) == 0 {
		return nil
	}

	chains := make(map[string]*ChainSnapshot)
	for _, mf := range mfs {
		switch mf.GetName() {
		case string(xmetrics.MetricChainErrorsCounter):
			for _, m := range mf.GetMetric() {
				chainName := metricLabel(m, "chain")
				nodeName := metricLabel(m, "node")
				if chainName == "" || nodeName == "" {
					continue
				}
				n := uint64(m.GetCounter().GetValue())
				cs := ensureChain(chains, chainName)
				cs.Stats.Errors += n
				ensureNode(cs, nodeName).Stats.Errors += n
			}
		case string(xmetrics.MetricNodeConnectDurationObserver):
			for _, m := range mf.GetMetric() {
				chainName := metricLabel(m, "chain")
				nodeName := metricLabel(m, "node")
				if chainName == "" || nodeName == "" {
					continue
				}
				h := m.GetHistogram()
				count := h.GetSampleCount()
				micros := uint64(h.GetSampleSum()*1e6 + 0.5)

				cs := ensureChain(chains, chainName)
				cs.Stats.ConnectCount += count
				cs.Stats.Connects = cs.Stats.ConnectCount
				cs.Stats.ConnectDurationSumMicros += micros

				ns := ensureNode(cs, nodeName)
				ns.Stats.ConnectCount += count
				ns.Stats.Connects = ns.Stats.ConnectCount
				ns.Stats.ConnectDurationSumMicros += micros
			}
		}
	}

	if len(chains) == 0 {
		return nil
	}
	return chains
}

func metricLabel(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func ensureChain(chains map[string]*ChainSnapshot, name string) *ChainSnapshot {
	if cs := chains[name]; cs != nil {
		return cs
	}
	cs := &ChainSnapshot{Name: name}
	chains[name] = cs
	return cs
}

func ensureNode(cs *ChainSnapshot, name string) *NodeSnapshot {
	for i := range cs.Nodes {
		if cs.Nodes[i].Name == name {
			return &cs.Nodes[i]
		}
	}
	cs.Nodes = append(cs.Nodes, NodeSnapshot{Name: name})
	return &cs.Nodes[len(cs.Nodes)-1]
}
