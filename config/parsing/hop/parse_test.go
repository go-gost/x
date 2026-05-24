package hop

import (
	"io"
	"testing"

	"github.com/go-gost/core/hop"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	xlogger "github.com/go-gost/x/logger"
	mdutil "github.com/go-gost/x/metadata/util"

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

func TestParseHop_Nil(t *testing.T) {
	h, err := ParseHop(nil, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseHop_PluginHTTP(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "http-hop",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_PluginGRPC(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "grpc-hop",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "hop.local",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_PluginDefaultType(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "default-hop",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_PluginHTTPWithTLS(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "http-tls-hop",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9003",
			TLS: &config.TLSConfig{
				Secure:     false,
				ServerName: "hop.example.com",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_PluginGRPCWithTLSInsecure(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "grpc-insecure-hop",
		Plugin: &config.PluginConfig{
			Type: "grpc",
			Addr: "127.0.0.1:9004",
			TLS: &config.TLSConfig{
				Secure: false, // InsecureSkipVerify = true
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_NoNodesNoPlugin(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name:  "empty-hop",
		Nodes: nil,
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop even with no nodes")
	}
}

func TestParseHop_WithBypass(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name:   "bypass-hop",
		Bypass: "bypass1",
		Bypasses: []string{"bypass2", "bypass3"},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_WithSelector(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "selector-hop",
		Selector: &config.SelectorConfig{
			Strategy: "round",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_WithNodeNilEntries(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "nil-nodes-hop",
		Nodes: []*config.NodeConfig{
			nil,
			nil,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop when nodes contain nil entries")
	}
}

func TestParseHop_SockOptsMark(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "sockopts-hop",
		SockOpts: &config.SockOptsConfig{
			Mark: 1234,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_MetadataSoMark(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "md-somark-hop",
		Metadata: map[string]any{
			parsing.MDKeySoMark: 5678,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_MetadataInterface(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "md-iface-hop",
		Metadata: map[string]any{
			parsing.MDKeyInterface: "eth0",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_MetadataProxyProtocol(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "md-ppv-hop",
		Metadata: map[string]any{
			parsing.MDKeyProxyProtocol: 2,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_MetadataNetns(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "md-netns-hop",
		Metadata: map[string]any{
			parsing.MDKeyNetns: "mynetns",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_InterfaceDeprecated(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name:      "iface-deprecated-hop",
		Interface: "eth1",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_FileLoader(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "file-hop",
		File: &config.FileLoader{Path: "/tmp/hop.txt"},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_HTTPLoader(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "http-hop",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/hop"},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_RedisLoader(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "redis-hop",
		Redis: &config.RedisLoader{
			Addr:     "127.0.0.1:6379",
			Key:      "hop-key",
			Username: "user",
			Password: "pass",
			DB:       1,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
}

func TestParseHop_NodeInheritsInterface(t *testing.T) {
	// When hop-level interface is set and node-level is not, node inherits.
	h, err := ParseHop(&config.HopConfig{
		Name:      "inherit-iface-hop",
		Interface: "eth0",
		Nodes: []*config.NodeConfig{
			{
				Name: "node1",
				Addr: "example.com:8080",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
	nodes := h.(hop.NodeList).Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if got := mdutil.GetString(nodes[0].Metadata(), parsing.MDKeyInterface); got != "eth0" {
		t.Fatalf("inherited interface = %q, want %q", got, "eth0")
	}
}

func TestParseHop_NodeInheritsSoMark(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "inherit-somark-hop",
		SockOpts: &config.SockOptsConfig{
			Mark: 9999,
		},
		Nodes: []*config.NodeConfig{
			{
				Name: "node1",
				Addr: "example.com:8080",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
	nodes := h.(hop.NodeList).Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if got := mdutil.GetInt(nodes[0].Metadata(), parsing.MDKeySoMark); got != 9999 {
		t.Fatalf("inherited so_mark = %d, want %d", got, 9999)
	}
}

func TestParseHop_NodeInheritsNetns(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name: "inherit-netns-hop",
		Metadata: map[string]any{
			parsing.MDKeyNetns: "mynetns",
		},
		Nodes: []*config.NodeConfig{
			{
				Name: "node1",
				Addr: "example.com:8080",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
	nodes := h.(hop.NodeList).Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if got := mdutil.GetString(nodes[0].Metadata(), parsing.MDKeyNetns); got != "mynetns" {
		t.Fatalf("inherited netns = %q, want %q", got, "mynetns")
	}
}

func TestParseHop_NodeResolverHostsInheritance(t *testing.T) {
	h, err := ParseHop(&config.HopConfig{
		Name:     "inherit-resolver-hop",
		Resolver: "my-resolver",
		Hosts:    "my-hosts",
		Nodes: []*config.NodeConfig{
			{
				Name: "node1",
				Addr: "example.com:8080",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil hop")
	}
	// Verify the node was created (no panic from nil resolver/hosts).
	// The resolver/hosts names are inherited, but registry lookup returns
	// nil since these names are not registered in this test.
	nodes := h.(hop.NodeList).Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
}
