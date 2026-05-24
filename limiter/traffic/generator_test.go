package traffic

import (
	"testing"
)

func TestLimitGenerator_In(t *testing.T) {
	g := newLimitGenerator(100, 0)
	lim := g.In()
	if lim == nil {
		t.Fatal("In() should not be nil for positive in")
	}
	if lim.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", lim.Limit())
	}

	// Each In() call creates a new instance.
	lim2 := g.In()
	if lim2 == lim {
		t.Fatal("each In() call should create a new instance")
	}
}

func TestLimitGenerator_In_Zero(t *testing.T) {
	g := newLimitGenerator(0, 200)
	if lim := g.In(); lim != nil {
		t.Fatal("In() should be nil for zero in")
	}
}

func TestLimitGenerator_Out(t *testing.T) {
	g := newLimitGenerator(0, 200)
	lim := g.Out()
	if lim == nil {
		t.Fatal("Out() should not be nil for positive out")
	}
	if lim.Limit() != 200 {
		t.Fatalf("expected limit 200, got %d", lim.Limit())
	}

	// Each Out() call creates a new instance.
	lim2 := g.Out()
	if lim2 == lim {
		t.Fatal("each Out() call should create a new instance")
	}
}

func TestLimitGenerator_Out_Zero(t *testing.T) {
	g := newLimitGenerator(100, 0)
	if lim := g.Out(); lim != nil {
		t.Fatal("Out() should be nil for zero out")
	}
}

func TestLimitGenerator_NilReceiver(t *testing.T) {
	var g *limitGenerator
	if lim := g.In(); lim != nil {
		t.Fatal("nil receiver In() should return nil")
	}
	if lim := g.Out(); lim != nil {
		t.Fatal("nil receiver Out() should return nil")
	}
}
