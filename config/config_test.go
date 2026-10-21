package config

import (
	"strings"
	"testing"
)

// TestSelectorConfigYAML locks in the YAML keys of the selector options.
// The config is decoded by viper/mapstructure, which matches the keys
// case-insensitively against the field names.
func TestSelectorConfigYAML(t *testing.T) {
	var c Config
	if err := c.Read(strings.NewReader(`
hops:
- name: hop0
  selector:
    strategy: parallel
    maxFails: 3
    failTimeout: 15s
    maxParallel: 4
    parallelMode: random
`), "yaml"); err != nil {
		t.Fatalf("read config: %v", err)
	}

	if len(c.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(c.Hops))
	}

	sel := c.Hops[0].Selector
	if sel == nil {
		t.Fatal("expected a selector config")
	}
	if sel.Strategy != "parallel" {
		t.Errorf("Strategy = %q, want %q", sel.Strategy, "parallel")
	}
	if sel.MaxFails != 3 {
		t.Errorf("MaxFails = %d, want %d", sel.MaxFails, 3)
	}
	if sel.FailTimeout.Seconds() != 15 {
		t.Errorf("FailTimeout = %v, want %v", sel.FailTimeout, 15*1e9)
	}
	if sel.MaxParallel != 4 {
		t.Errorf("MaxParallel = %d, want %d", sel.MaxParallel, 4)
	}
	if sel.ParallelMode != "random" {
		t.Errorf("ParallelMode = %q, want %q", sel.ParallelMode, "random")
	}
}
