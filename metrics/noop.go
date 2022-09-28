package metrics

import "github.com/go-gost/core/metrics"

var (
	nopGauge    = &noopGauge{}
	nopCounter  = &noopCounter{}
	nopObserver = &noopObserver{}

	noop metrics.Metrics = &noopMetrics{}
)

type noopMetrics struct{}

func Noop() metrics.Metrics {
	return noop
}

func (m *noopMetrics) Counter(name metrics.MetricName, labels metrics.Labels) metrics.Counter {
	return nopCounter
}

func (m *noopMetrics) Gauge(name metrics.MetricName, labels metrics.Labels) metrics.Gauge {
	return nopGauge
}

func (m *noopMetrics) Observer(name metrics.MetricName, labels metrics.Labels) metrics.Observer {
	return nopObserver
}

type noopGauge struct{}

func (*noopGauge) Inc()          {}
func (*noopGauge) Dec()          {}
func (*noopGauge) Add(v float64) {}
func (*noopGauge) Set(v float64) {}

type noopCounter struct{}

func (*noopCounter) Inc()          {}
func (*noopCounter) Add(v float64) {}

type noopObserver struct{}

func (*noopObserver) Observe(v float64) {}
