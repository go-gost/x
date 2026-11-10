package metrics

import (
	"github.com/go-gost/core/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// GatherFamilies returns only the requested metric families from the default
// registry. Unknown and duplicate names are ignored.
func GatherFamilies(names ...metrics.MetricName) ([]*dto.MetricFamily, error) {
	m, ok := defaultMetrics.(*promMetrics)
	if !ok {
		return nil, nil
	}

	reg := prometheus.NewRegistry()
	seen := make(map[metrics.MetricName]struct{}, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		if v, ok := m.counters[name]; ok {
			reg.MustRegister(v)
		}
		if v, ok := m.gauges[name]; ok {
			reg.MustRegister(v)
		}
		if v, ok := m.histograms[name]; ok {
			reg.MustRegister(v)
		}
	}

	return reg.Gather()
}
