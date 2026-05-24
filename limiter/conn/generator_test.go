package conn

import (
	"testing"
)

func TestConnLimitGenerator(t *testing.T) {
	g := NewConnLimitGenerator(5)
	lim := g.Limiter()
	if lim == nil {
		t.Fatal("Limiter() should not be nil for non-zero limit")
	}
	if lim.Limit() != 5 {
		t.Fatalf("expected limit 5, got %d", lim.Limit())
	}

	// Each Limiter() call creates a new instance.
	lim2 := g.Limiter()
	if lim2 == lim {
		t.Fatal("each Limiter() call should create a new instance")
	}
}

func TestConnLimitGenerator_Zero(t *testing.T) {
	g := NewConnLimitGenerator(0)
	if g == nil {
		t.Fatal("generator should not be nil")
	}
	if lim := g.Limiter(); lim != nil {
		t.Fatal("Limiter() should be nil for zero limit")
	}
}

func TestConnLimitGenerator_Negative(t *testing.T) {
	g := NewConnLimitGenerator(-5)
	if lim := g.Limiter(); lim != nil {
		t.Fatal("Limiter() should be nil for negative limit")
	}
}

func TestConnLimitGenerator_NilReceiver(t *testing.T) {
	var g *connLimitGenerator
	if lim := g.Limiter(); lim != nil {
		t.Fatal("nil receiver Limiter() should return nil")
	}
}

func TestConnLimitSingleGenerator(t *testing.T) {
	g := NewConnLimitSingleGenerator(5)
	lim := g.Limiter()
	if lim == nil {
		t.Fatal("Limiter() should not be nil")
	}
	if lim.Limit() != 5 {
		t.Fatalf("expected limit 5, got %d", lim.Limit())
	}

	// Same instance every call.
	lim2 := g.Limiter()
	if lim2 != lim {
		t.Fatal("single generator should return same instance")
	}
}

func TestConnLimitSingleGenerator_Zero(t *testing.T) {
	g := NewConnLimitSingleGenerator(0)
	if lim := g.Limiter(); lim != nil {
		t.Fatal("Limiter() should be nil for zero limit")
	}
}

func TestConnLimitSingleGenerator_Negative(t *testing.T) {
	g := NewConnLimitSingleGenerator(-1)
	if lim := g.Limiter(); lim != nil {
		t.Fatal("Limiter() should be nil for negative limit")
	}
}

func TestConnLimitSingleGenerator_NilReceiver(t *testing.T) {
	var g *connLimitSingleGenerator
	if lim := g.Limiter(); lim != nil {
		t.Fatal("nil receiver Limiter() should return nil")
	}
}
