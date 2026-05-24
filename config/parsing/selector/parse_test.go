package selector

import (
	"testing"

	"github.com/go-gost/x/config"
)

func TestParseChainSelector_Nil(t *testing.T) {
	sel := ParseChainSelector(nil)
	if sel != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseChainSelector_RoundRobin(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "round"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_RR(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "rr"})
	if sel == nil {
		t.Fatal("expected non-nil selector for rr strategy")
	}
}

func TestParseChainSelector_Random(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "random"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_Rand(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "rand"})
	if sel == nil {
		t.Fatal("expected non-nil selector for rand strategy")
	}
}

func TestParseChainSelector_FIFO(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "fifo"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_HA(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "ha"})
	if sel == nil {
		t.Fatal("expected non-nil selector for ha strategy")
	}
}

func TestParseChainSelector_Hash(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "hash"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_DefaultStrategy(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "unknown"})
	if sel == nil {
		t.Fatal("expected non-nil selector for unknown strategy (should default to round-robin)")
	}
}

func TestParseChainSelector_WithMaxFails(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{
		Strategy:    "round",
		MaxFails:    3,
		FailTimeout: 0,
	})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Nil(t *testing.T) {
	sel := ParseNodeSelector(nil)
	if sel != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseNodeSelector_RoundRobin(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "round"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Random(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "random"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_FIFO(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "fifo"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Hash(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "hash"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Parallel(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "parallel"})
	if sel == nil {
		t.Fatal("expected non-nil selector for parallel strategy")
	}
}

func TestParseNodeSelector_DefaultStrategy(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "unknown"})
	if sel == nil {
		t.Fatal("expected non-nil selector for unknown strategy (should default to round-robin)")
	}
}

func TestDefaultNodeSelector(t *testing.T) {
	sel := DefaultNodeSelector()
	if sel == nil {
		t.Fatal("expected non-nil default node selector")
	}
}

func TestDefaultChainSelector(t *testing.T) {
	sel := DefaultChainSelector()
	if sel == nil {
		t.Fatal("expected non-nil default chain selector")
	}
}
