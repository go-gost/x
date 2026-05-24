package resolver

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

func TestParseResolver_Nil(t *testing.T) {
	r, err := ParseResolver(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseResolver_PluginHTTP(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name: "http-res",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestParseResolver_PluginGRPC(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name: "grpc-res",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "resolver.local",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestParseResolver_PluginDefaultType(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name: "default-res",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestParseResolver_WithNameservers(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name: "ns-res",
		Nameservers: []*config.NameserverConfig{
			{Addr: "8.8.8.8", Prefer: "ipv4"},
			{Addr: "8.8.4.4", Prefer: "ipv4"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestParseResolver_EmptyNameservers(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name:        "empty-ns",
		Nameservers: []*config.NameserverConfig{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver even with empty nameservers")
	}
}

func TestParseResolver_NameserverWithClientIP(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name: "clientip-res",
		Nameservers: []*config.NameserverConfig{
			{Addr: "8.8.8.8", ClientIP: "1.2.3.4"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestParseResolver_NameserverWithAllFields(t *testing.T) {
	r, err := ParseResolver(&config.ResolverConfig{
		Name: "full-res",
		Nameservers: []*config.NameserverConfig{
			{
				Addr:     "8.8.8.8:53",
				Chain:    "chain1",
				Prefer:   "ipv4",
				ClientIP: "1.2.3.4",
				Hostname: "dns.example.com",
				TTL:      300,
				Timeout:  5,
				Async:    true,
				Only:     "A",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}
