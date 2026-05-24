package metrics

import (
	"testing"

	"github.com/go-gost/core/metrics"
)

func TestNoopReturnsSingleton(t *testing.T) {
	n1 := Noop()
	n2 := Noop()
	if n1 != n2 {
		t.Error("Noop() should return the same instance every time")
	}
}

func TestNoopMetricsCounter(t *testing.T) {
	c := Noop().Counter("any", nil)
	if c == nil {
		t.Fatal("noop Counter should not be nil")
	}
	c.Inc()
	c.Add(42)
}

func TestNoopMetricsGauge(t *testing.T) {
	g := Noop().Gauge("any", nil)
	if g == nil {
		t.Fatal("noop Gauge should not be nil")
	}
	g.Inc()
	g.Dec()
	g.Add(1.5)
	g.Set(100)
}

func TestNoopMetricsObserver(t *testing.T) {
	o := Noop().Observer("any", nil)
	if o == nil {
		t.Fatal("noop Observer should not be nil")
	}
	o.Observe(0.5)
}

func TestNoopMetricsSameInstances(t *testing.T) {
	m := Noop()
	// Each call returns the shared singleton noop instances
	if m.Counter("a", nil) != m.Counter("b", nil) {
		t.Error("noop Counter should return same instance regardless of name")
	}
	if m.Gauge("a", nil) != m.Gauge("b", nil) {
		t.Error("noop Gauge should return same instance regardless of name")
	}
	if m.Observer("a", nil) != m.Observer("b", nil) {
		t.Error("noop Observer should return same instance regardless of name")
	}
}

func TestNoopPackageVarsAreNoopTypes(t *testing.T) {
	// The package-level noop variables should be instances of the concrete noop types.
	// These are the values returned by GetCounter/Gauge/Observer when disabled.
	c := Noop().Counter("x", metrics.Labels{"k": "v"})
	if c == nil {
		t.Fatal("noop Counter from Noop() should not be nil")
	}
	c.Inc()
	c.Add(10)

	g := Noop().Gauge("x", metrics.Labels{"k": "v"})
	if g == nil {
		t.Fatal("noop Gauge from Noop() should not be nil")
	}
	g.Set(5)

	o := Noop().Observer("x", metrics.Labels{"k": "v"})
	if o == nil {
		t.Fatal("noop Observer from Noop() should not be nil")
	}
	o.Observe(0.1)
}
