package node

import (
	"io"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
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

func TestParseNode_Nil(t *testing.T) {
	n, err := ParseNode("test-hop", nil, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseNode_Defaults(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "node1",
		Addr: "example.com:8080",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_DefaultsEmptyName(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "",
		Addr: "example.com:8080",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_DefaultsEmptyAddr(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "no-addr",
		Addr: "",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_ExplicitConnector(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "explicit-conn",
		Addr: "example.com:8080",
		Connector: &config.ConnectorConfig{
			Type: "http",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_UnregisteredConnector(t *testing.T) {
	_, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "bad-conn",
		Addr: "example.com:8080",
		Connector: &config.ConnectorConfig{
			Type: "nonexistent-connector-type",
		},
	}, testLogger())
	if err == nil {
		t.Fatal("expected error for unregistered connector type")
	}
}

func TestParseNode_UnregisteredDialer(t *testing.T) {
	_, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "bad-dial",
		Addr: "example.com:8080",
		Dialer: &config.DialerConfig{
			Type: "nonexistent-dialer-type",
		},
	}, testLogger())
	if err == nil {
		t.Fatal("expected error for unregistered dialer type")
	}
}

func TestParseNode_ExplicitDialer(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "explicit-dial",
		Addr: "example.com:8080",
		Dialer: &config.DialerConfig{
			Type: "tcp",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithBypass(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name:     "bypass-node",
		Addr:     "example.com:8080",
		Bypass:   "bp1",
		Bypasses: []string{"bp2", "bp3"},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithResolver(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name:     "resolver-node",
		Addr:     "example.com:8080",
		Resolver: "my-resolver",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithHosts(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name:  "hosts-node",
		Addr:  "example.com:8080",
		Hosts: "my-hosts",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithNetwork(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name:    "network-node",
		Addr:    "example.com:8080",
		Network: "tcp",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithMetadata(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "meta-node",
		Addr: "example.com:8080",
		Metadata: map[string]any{
			parsing.MDKeySoMark:    1234,
			parsing.MDKeyInterface: "eth0",
			parsing.MDKeyNetns:     "myns",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithSockOpts(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "sockopts-node",
		Addr: "example.com:8080",
		SockOpts: &config.SockOptsConfig{
			Mark: 9999,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithFilter(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "filter-node",
		Addr: "example.com:8080",
		Filter: &config.NodeFilterConfig{
			Protocol: "http",
			Host:     "*.example.com",
			Path:     "/api",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithFilterStarBare(t *testing.T) {
	// "*example.com" should become ".example.com"
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "star-bare-node",
		Addr: "example.com:8080",
		Filter: &config.NodeFilterConfig{
			Host: "*example.com",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithMatcher(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "matcher-node",
		Addr: "example.com:8080",
		Matcher: &config.NodeMatcherConfig{
			Rule:     "dstport==80",
			Priority: 10,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithMatcherAutoPriority(t *testing.T) {
	// Priority auto-set to len(rule) when zero
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "auto-prio-node",
		Addr: "example.com:8080",
		Matcher: &config.NodeMatcherConfig{
			Rule:     "dstport==443",
			Priority: 0,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithMatcherBodySize(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "body-node",
		Addr: "example.com:8080",
		Matcher: &config.NodeMatcherConfig{
			// Escaped predicate form; in YAML users write the backtick
			// equivalent: BodyRegexp(`"model":"gpt-4"`).
			Rule:     `BodyRegexp("\"model\":\"gpt-4\"")`,
			BodySize: 65536,
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	if got := n.Options().MatcherBodySize; got != 65536 {
		t.Errorf("MatcherBodySize = %d, want 65536", got)
	}
}

func TestParseNode_WithMatcherBodySize_Clamped(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "body-node",
		Addr: "example.com:8080",
		Matcher: &config.NodeMatcherConfig{
			Rule:     `BodyRegexp("foo")`,
			BodySize: 10 * 1024 * 1024, // 10MB, above the 1MB cap
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	if got := n.Options().MatcherBodySize; got != MaxMatcherBodySize {
		t.Errorf("MatcherBodySize = %d, want %d (clamped)", got, MaxMatcherBodySize)
	}
}

func TestParseNode_WithHTTPNode(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "http-node",
		Addr: "example.com:8080",
		HTTP: &config.HTTPNodeConfig{
			Host:           "custom.example.com",
			RequestHeader:  map[string]string{"X-Custom": "value"},
			ResponseHeader: map[string]string{"X-Response": "value"},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithHTTPAuth(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "http-auth-node",
		Addr: "example.com:8080",
		HTTP: &config.HTTPNodeConfig{
			Auth: &config.AuthConfig{
				Username: "user",
				Password: "pass",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithHTTPDeprecatedHeader(t *testing.T) {
	// Deprecated Header field should populate RequestHeader
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "http-deprecated-node",
		Addr: "example.com:8080",
		HTTP: &config.HTTPNodeConfig{
			Header: map[string]string{"X-Old": "value"},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_WithTLSNode(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "tls-node",
		Addr: "example.com:8080",
		TLS: &config.TLSNodeConfig{
			ServerName: "secure.example.com",
			Secure:     true,
			Options: &config.TLSOptions{
				MinVersion:   "1.2",
				MaxVersion:   "1.3",
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				ALPN:         []string{"h2", "http/1.1"},
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_TLSServerNameFromAddr(t *testing.T) {
	// When connector/dialer TLS ServerName is empty, it defaults from addr hostname.
	// The server name is set on the connector's TLS config (internal), so the best
	// verification is that ParseNode does not error and returns a node.
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "tls-servername-node",
		Addr: "tls.example.com:443",
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_ConnectorAuth(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "conn-auth-node",
		Addr: "example.com:8080",
		Connector: &config.ConnectorConfig{
			Type: "http",
			Auth: &config.AuthConfig{
				Username: "connuser",
				Password: "connpass",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_DialerAuth(t *testing.T) {
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "dial-auth-node",
		Addr: "example.com:8080",
		Dialer: &config.DialerConfig{
			Type: "tcp",
			Auth: &config.AuthConfig{
				Username: "dialuser",
				Password: "dialpass",
			},
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestParseNode_InvalidMatcherRule(t *testing.T) {
	// An invalid matcher rule sets priority to -1
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "invalid-matcher-node",
		Addr: "example.com:8080",
		Matcher: &config.NodeMatcherConfig{
			Rule: "",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node even with empty matcher rule")
	}
}

func TestParseNode_DeprecatedFilterFields(t *testing.T) {
	// Deprecated filter fields: Protocol/Host/Path via Filter
	n, err := ParseNode("test-hop", &config.NodeConfig{
		Name: "deprecated-node",
		Addr: "example.com:8080",
		Filter: &config.NodeFilterConfig{
			Protocol: "socks5",
			Host:     "*.example.com",
			Path:     "/proxy",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}
