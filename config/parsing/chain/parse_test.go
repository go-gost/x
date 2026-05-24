package chain

import (
	"io"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
)

func TestMain(m *testing.M) {
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))
	m.Run()
}

func testLogger() logger.Logger {
	return xlogger.NewLogger(xlogger.OutputOption(io.Discard))
}

func TestParseChain_Nil(t *testing.T) {
	c, err := ParseChain(nil, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseChain_EmptyHops(t *testing.T) {
	c, err := ParseChain(&config.ChainConfig{
		Name: "empty-hops",
		Hops: []*config.HopConfig{},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil chain")
	}
}

func TestParseChain_NilHops(t *testing.T) {
	c, err := ParseChain(&config.ChainConfig{
		Name: "nil-hops",
		Hops: nil,
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil chain")
	}
}

func TestParseChain_NilHopEntry(t *testing.T) {
	c, err := ParseChain(&config.ChainConfig{
		Name: "nil-entry",
		Hops: []*config.HopConfig{nil},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil chain when hop entry is nil")
	}
}

func TestParseChain_WithMetadata(t *testing.T) {
	c, err := ParseChain(&config.ChainConfig{
		Name: "meta-chain",
		Metadata: map[string]any{
			"key": "value",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil chain")
	}
}

func TestParseChain_NamedHop(t *testing.T) {
	// Named hop (Nodes==nil, Plugin==nil) uses registry lookup
	c, err := ParseChain(&config.ChainConfig{
		Name: "named-hop",
		Hops: []*config.HopConfig{
			{Name: "nonexistent-hop"},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil chain even with unregistered hop")
	}
}

func TestParseChain_InlineHopWithPlugin(t *testing.T) {
	// Inline hop (Nodes!=nil or Plugin!=nil) calls hop_parser.ParseHop
	c, err := ParseChain(&config.ChainConfig{
		Name: "inline-hop",
		Hops: []*config.HopConfig{
			{
				Name: "plugin-hop",
				Plugin: &config.PluginConfig{
					Type: "http",
					Addr: "127.0.0.1:9000",
				},
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil chain")
	}
}
