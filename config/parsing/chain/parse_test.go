package chain

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"

	// Register connector and dialer implementations needed for node parsing.
	_ "github.com/go-gost/x/connector/http"
	_ "github.com/go-gost/x/dialer/tcp"
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

// TestParseChain_InlineHopWithFileLoader is a regression test for inline chain
// hops that only declare a file source (no nodes, no plugin). Such hops must
// be parsed inline instead of silently falling back to the hop registry,
// which returns an empty wrapper for an unknown name.
func TestParseChain_InlineHopWithFileLoader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, []byte(`[{"name":"n1","addr":"127.0.0.1:8080"}]`), 0o644); err != nil {
		t.Fatalf("write nodes file: %v", err)
	}

	c, err := ParseChain(&config.ChainConfig{
		Name: "inline-file-hop-chain",
		Hops: []*config.HopConfig{
			{
				Name: "file-hop",
				File: &config.FileLoader{Path: path},
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	defer c.(io.Closer).Close()

	// The file source is loaded asynchronously by the hop's reload goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		route := c.Route(context.Background(), "tcp", "example.com:80")
		if route != nil && len(route.Nodes()) == 1 {
			if route.Nodes()[0].Addr != "127.0.0.1:8080" {
				t.Fatalf("route node addr = %q, want 127.0.0.1:8080", route.Nodes()[0].Addr)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("inline file hop not loaded: route has %d nodes", len(route.Nodes()))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
