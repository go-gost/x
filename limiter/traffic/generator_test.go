package traffic

import (
	"context"
	"testing"
)

func TestLimitGenerator_In(t *testing.T) {
	g := newLimitGenerator(100, 0, 0)
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
	g := newLimitGenerator(0, 200, 0)
	if lim := g.In(); lim != nil {
		t.Fatal("In() should be nil for zero in")
	}
}

func TestLimitGenerator_Out(t *testing.T) {
	g := newLimitGenerator(0, 200, 0)
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
	g := newLimitGenerator(100, 0, 0)
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

func TestLimitGenerator_Burst(t *testing.T) {
	// Burst specified: should use NewLimiterWithBurst.
	g := newLimitGenerator(100, 200, 500)
	limIn := g.In()
	if limIn == nil {
		t.Fatal("In() should not be nil")
	}
	if limIn.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", limIn.Limit())
	}
	// With burst=500, Wait for 500 should succeed immediately.
	if n := limIn.Wait(context.Background(), 500); n != 500 {
		t.Fatalf("expected 500 with burst, got %d", n)
	}

	limOut := g.Out()
	if limOut == nil {
		t.Fatal("Out() should not be nil")
	}
	if limOut.Limit() != 200 {
		t.Fatalf("expected limit 200, got %d", limOut.Limit())
	}
}
