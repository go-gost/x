package metrics

import (
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

func NewMetrics() metrics.Metrics {
	host, _ := os.Hostname()
	m := &promMetrics{
		host: host,
		gauges: map[metrics.MetricName]*prometheus.GaugeVec{
			metrics.MetricServicesGauge: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: string(metrics.MetricServicesGauge),
					Help: "Current number of services",
				},
				[]string{"host"}),
			metrics.MetricServiceRequestsInFlightGauge: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: string(metrics.MetricServiceRequestsInFlightGauge),
					Help: "Current in-flight requests",
				},
				[]string{"host", "service"}),
		},
		counters: map[metrics.MetricName]*prometheus.CounterVec{
			metrics.MetricServiceRequestsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(metrics.MetricServiceRequestsCounter),
					Help: "Total number of requests",
				},
				[]string{"host", "service"}),
			metrics.MetricServiceTransferInputBytesCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(metrics.MetricServiceTransferInputBytesCounter),
					Help: "Total service input data transfer size in bytes",
				},
				[]string{"host", "service"}),
			metrics.MetricServiceTransferOutputBytesCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(metrics.MetricServiceTransferOutputBytesCounter),
					Help: "Total service output data transfer size in bytes",
				},
				[]string{"host", "service"}),
			metrics.MetricServiceHandlerErrorsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(metrics.MetricServiceHandlerErrorsCounter),
					Help: "Total service handler errors",
				},
				[]string{"host", "service"}),
			metrics.MetricChainErrorsCounter: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: string(metrics.MetricChainErrorsCounter),
					Help: "Total chain errors",
				},
				[]string{"host", "chain", "node"}),
		},
		histograms: map[metrics.MetricName]*prometheus.HistogramVec{
			metrics.MetricServiceRequestsDurationObserver: prometheus.NewHistogramVec(
				prometheus.HistogramOpts{
					Name: string(metrics.MetricServiceRequestsDurationObserver),
					Help: "Distribution of request latencies",
					Buckets: []float64{
						.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 15, 30, 60,
					},
				},
				[]string{"host", "service"}),
			metrics.MetricNodeConnectDurationObserver: prometheus.NewHistogramVec(
				prometheus.HistogramOpts{
					Name: string(metrics.MetricNodeConnectDurationObserver),
					Help: "Distribution of chain node connect latencies",
					Buckets: []float64{
						.01, .05, .1, .25, .5, 1, 1.5, 2, 5, 10, 15, 30, 60,
					},
				},
				[]string{"host", "chain", "node"}),
		},
	}
	for k := range m.gauges {
		prometheus.MustRegister(m.gauges[k])
	}
	for k := range m.counters {
		prometheus.MustRegister(m.counters[k])
	}
	for k := range m.histograms {
		prometheus.MustRegister(m.histograms[k])
	}

	return m
}

func (m *promMetrics) Gauge(name metrics.MetricName, labels metrics.Labels) metrics.Gauge {
	v, ok := m.gauges[name]
	if !ok {
		return nil
	}
	if labels == nil {
		labels = metrics.Labels{}
	}
	labels["host"] = m.host
	return v.With(prometheus.Labels(labels))
}

func (m *promMetrics) Counter(name metrics.MetricName, labels metrics.Labels) metrics.Counter {
	v, ok := m.counters[name]
	if !ok {
		return nil
	}
	if labels == nil {
		labels = metrics.Labels{}
	}
	labels["host"] = m.host
	return v.With(prometheus.Labels(labels))
}

func (m *promMetrics) Observer(name metrics.MetricName, labels metrics.Labels) metrics.Observer {
	v, ok := m.histograms[name]
	if !ok {
		return nil
	}
	if labels == nil {
		labels = metrics.Labels{}
	}
	labels["host"] = m.host
	return v.With(prometheus.Labels(labels))
}
