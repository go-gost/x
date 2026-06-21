package metrics

import (
	"maps"
	"os"

	"github.com/go-gost/core/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type promMetrics struct {
	host       string
	gauges     map[metrics.MetricName]*prometheus.GaugeVec
	counters   map[metrics.MetricName]*prometheus.CounterVec
	histograms map[metrics.MetricName]*prometheus.HistogramVec
}

// NewMetrics returns a Prometheus-based Metrics implementation. All metrics are
// registered with the given registry. Use nil to register with the default
// Prometheus registry.
func NewMetrics(reg *prometheus.Registry) metrics.Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer.(*prometheus.Registry)
	}

	host, _ := os.Hostname()
	m := &promMetrics{
		host: host,
		gauges: map[metrics.MetricName]*prometheus.GaugeVec{
			MetricServicesGauge: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: string(MetricServicesGauge),
					Help: "Current number of services",
				},
				[]string{"host"}),
			MetricServiceRequestsInFlightGauge: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: string(MetricServiceRequestsInFlightGauge),
					Help: "Current in-flight requests",
				},
				[]string{"host", "service", "client"}),
		},
		counters: map[metrics.MetricName]*prometheus.CounterVec{
			MetricServiceRequestsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(MetricServiceRequestsCounter),
					Help: "Total number of requests",
				},
				[]string{"host", "service", "client"}),
			MetricServiceTransferInputBytesCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(MetricServiceTransferInputBytesCounter),
					Help: "Total service input data transfer size in bytes",
				},
				[]string{"host", "service", "client"}),
			MetricServiceTransferOutputBytesCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(MetricServiceTransferOutputBytesCounter),
					Help: "Total service output data transfer size in bytes",
				},
				[]string{"host", "service", "client"}),
			MetricServiceHandlerErrorsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(MetricServiceHandlerErrorsCounter),
					Help: "Total service handler errors",
				},
				[]string{"host", "service", "client"}),
			MetricChainErrorsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(MetricChainErrorsCounter),
					Help: "Total chain errors",
				},
				[]string{"host", "chain", "node"}),
			MetricRecorderRecordsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(MetricRecorderRecordsCounter),
					Help: "Total records written by recorder",
				},
				[]string{"host", "recorder"}),
		},
		histograms: map[metrics.MetricName]*prometheus.HistogramVec{
			MetricServiceRequestsDurationObserver: prometheus.NewHistogramVec(
				prometheus.HistogramOpts{
					Name: string(MetricServiceRequestsDurationObserver),
					Help: "Distribution of request latencies",
					Buckets: []float64{
						.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 15, 30, 60,
					},
				},
				[]string{"host", "service"}),
			MetricNodeConnectDurationObserver: prometheus.NewHistogramVec(
				prometheus.HistogramOpts{
					Name: string(MetricNodeConnectDurationObserver),
					Help: "Distribution of chain node connect latencies",
					Buckets: []float64{
						.01, .05, .1, .25, .5, 1, 1.5, 2, 5, 10, 15, 30, 60,
					},
				},
				[]string{"host", "chain", "node"}),
		},
	}
	for k := range m.gauges {
		reg.MustRegister(m.gauges[k])
	}
	for k := range m.counters {
		reg.MustRegister(m.counters[k])
	}
	for k := range m.histograms {
		reg.MustRegister(m.histograms[k])
	}

	return m
}

func (m *promMetrics) Gauge(name metrics.MetricName, labels metrics.Labels) metrics.Gauge {
	v, ok := m.gauges[name]
	if !ok {
		return nopGauge
	}
	plabels := prometheus.Labels{}
	maps.Copy(plabels, labels)
	plabels["host"] = m.host
	return v.With(plabels)
}

func (m *promMetrics) Counter(name metrics.MetricName, labels metrics.Labels) metrics.Counter {
	v, ok := m.counters[name]
	if !ok {
		return nopCounter
	}
	plabels := prometheus.Labels{}
	maps.Copy(plabels, labels)
	plabels["host"] = m.host
	return v.With(plabels)
}

func (m *promMetrics) Observer(name metrics.MetricName, labels metrics.Labels) metrics.Observer {
	v, ok := m.histograms[name]
	if !ok {
		return nopObserver
	}
	plabels := prometheus.Labels{}
	maps.Copy(plabels, labels)
	plabels["host"] = m.host
	return v.With(plabels)
}
