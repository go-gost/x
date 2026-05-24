package metrics

import (
	"testing"

	"github.com/go-gost/core/metrics"
)

func TestEnableDisable(t *testing.T) {
	// Save and restore original state.
	orig := IsEnabled()
	defer Enable(orig)

	Enable(false)
	if IsEnabled() {
		t.Error("IsEnabled should return false after Enable(false)")
	}

	Enable(true)
	if !IsEnabled() {
		t.Error("IsEnabled should return true after Enable(true)")
	}

	Enable(false)
	if IsEnabled() {
		t.Error("IsEnabled should return false after second Enable(false)")
	}
}

func TestGetCounterDisabled(t *testing.T) {
	orig := IsEnabled()
	Enable(false)
	defer Enable(orig)

	c := GetCounter(MetricServiceRequestsCounter, metrics.Labels{"service": "s", "client": "c"})
	if c == nil {
		t.Error("GetCounter should not return nil when disabled")
	}
	// Should be noop — calling methods must not panic.
	c.Inc()
	c.Add(42)
	c.Add(-1)
}

func TestGetGaugeDisabled(t *testing.T) {
	orig := IsEnabled()
	Enable(false)
	defer Enable(orig)

	// MetricServicesGauge has only ["host"] label (auto-added), so pass no extra labels.
	g := GetGauge(MetricServicesGauge, nil)
	if g == nil {
		t.Error("GetGauge should not return nil when disabled")
	}
	g.Inc()
	g.Dec()
	g.Add(1.5)
	g.Set(100)
	g.Set(-1)
}

func TestGetObserverDisabled(t *testing.T) {
	orig := IsEnabled()
	Enable(false)
	defer Enable(orig)

	o := GetObserver(MetricServiceRequestsDurationObserver, metrics.Labels{"service": "s"})
	if o == nil {
		t.Error("GetObserver should not return nil when disabled")
	}
	o.Observe(0.5)
	o.Observe(0)
	o.Observe(-1)
}

func TestGetCounterEnabled(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	c := GetCounter(MetricServiceRequestsCounter, metrics.Labels{"service": "s", "client": "c"})
	if c == nil {
		t.Error("GetCounter should not return nil when enabled")
	}
	// Methods should not panic.
	c.Inc()
	c.Add(10)
}

func TestGetGaugeEnabled(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	// MetricServicesGauge has only ["host"] label (auto-added).
	g := GetGauge(MetricServicesGauge, nil)
	if g == nil {
		t.Error("GetGauge should not return nil when enabled")
	}
	g.Inc()
	g.Dec()
	g.Set(5)
}

func TestGetObserverEnabled(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	o := GetObserver(MetricServiceRequestsDurationObserver, metrics.Labels{"service": "s"})
	if o == nil {
		t.Error("GetObserver should not return nil when enabled")
	}
	o.Observe(0.25)
}

func TestGetCounterEnabledUnknownName(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	c := GetCounter("nonexistent_metric", nil)
	if c == nil {
		t.Error("GetCounter should not return nil for unknown metric name")
	}
	c.Inc()
	c.Add(5)
}

func TestGetGaugeEnabledUnknownName(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	g := GetGauge("nonexistent_metric", nil)
	if g == nil {
		t.Error("GetGauge should not return nil for unknown metric name")
	}
	g.Inc()
	g.Set(1)
}

func TestGetObserverEnabledUnknownName(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	o := GetObserver("nonexistent_metric", nil)
	if o == nil {
		t.Error("GetObserver should not return nil for unknown metric name")
	}
	o.Observe(1.0)
}

func TestMetricConstantsNotEmpty(t *testing.T) {
	names := []metrics.MetricName{
		MetricServicesGauge,
		MetricServiceRequestsCounter,
		MetricServiceRequestsInFlightGauge,
		MetricServiceRequestsDurationObserver,
		MetricServiceTransferInputBytesCounter,
		MetricServiceTransferOutputBytesCounter,
		MetricNodeConnectDurationObserver,
		MetricServiceHandlerErrorsCounter,
		MetricChainErrorsCounter,
		MetricRecorderRecordsCounter,
	}
	for i, n := range names {
		if n == "" {
			t.Errorf("metric constant at index %d is empty", i)
		}
	}
}
