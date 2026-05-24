package metrics

import (
	"testing"

	"github.com/go-gost/core/metrics"
)

func TestPromMetricsGaugeHostLabel(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	// MetricServicesGauge: labels=["host"], host auto-added.
	g := GetGauge(MetricServicesGauge, nil)
	if g == nil {
		t.Fatal("gauge should not be nil")
	}
	g.Set(3)
	g.Add(1)
	g.Inc()
	g.Dec()
}

func TestPromMetricsCounterKnownNames(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	tests := []struct {
		name   metrics.MetricName
		labels metrics.Labels
	}{
		{MetricServiceRequestsCounter, metrics.Labels{"service": "s", "client": "c"}},
		{MetricServiceTransferInputBytesCounter, metrics.Labels{"service": "s", "client": "c"}},
		{MetricServiceTransferOutputBytesCounter, metrics.Labels{"service": "s", "client": "c"}},
		{MetricServiceHandlerErrorsCounter, metrics.Labels{"service": "s", "client": "c"}},
		{MetricChainErrorsCounter, metrics.Labels{"chain": "ch", "node": "n"}},
		{MetricRecorderRecordsCounter, metrics.Labels{"recorder": "r"}},
	}

	for _, tt := range tests {
		c := GetCounter(tt.name, tt.labels)
		if c == nil {
			t.Errorf("GetCounter(%q) returned nil", tt.name)
			continue
		}
		c.Inc()
		c.Add(10)
	}
}

func TestPromMetricsGaugeKnownNames(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	g := GetGauge(MetricServiceRequestsInFlightGauge, metrics.Labels{"service": "s", "client": "c"})
	if g == nil {
		t.Fatal("gauge should not be nil")
	}
	g.Set(1)
	g.Inc()
	g.Dec()
}

func TestPromMetricsObserverKnownNames(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	tests := []struct {
		name   metrics.MetricName
		labels metrics.Labels
	}{
		{MetricServiceRequestsDurationObserver, metrics.Labels{"service": "s"}},
		{MetricNodeConnectDurationObserver, metrics.Labels{"chain": "ch", "node": "n"}},
	}

	for _, tt := range tests {
		o := GetObserver(tt.name, tt.labels)
		if o == nil {
			t.Errorf("GetObserver(%q) returned nil", tt.name)
			continue
		}
		o.Observe(0.5)
		o.Observe(1.0)
	}
}

func TestPromMetricsUnknownNameReturnsNoop(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	// Unknown metric names should return noop implementations (non-nil, safe to call).
	c := GetCounter("unknown_counter", nil)
	if c == nil {
		t.Error("counter for unknown name should not be nil")
	}
	c.Inc()

	g := GetGauge("unknown_gauge", nil)
	if g == nil {
		t.Error("gauge for unknown name should not be nil")
	}
	g.Set(1)

	o := GetObserver("unknown_observer", nil)
	if o == nil {
		t.Error("observer for unknown name should not be nil")
	}
	o.Observe(0.1)
}
