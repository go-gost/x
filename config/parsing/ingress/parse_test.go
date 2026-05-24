package ingress

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

func TestParseIngress_Nil(t *testing.T) {
	ing := ParseIngress(nil)
	if ing != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseIngress_PluginHTTP(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "http-ing",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_PluginGRPC(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "grpc-ing",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "ingress.local",
			},
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_PluginDefaultType(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "default-ing",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_WithRules(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "rule-ing",
		Rules: []*config.IngressRuleConfig{
			{Hostname: "example.com", Endpoint: "10.0.0.1:8080"},
			{Hostname: "test.com", Endpoint: "10.0.0.2:9090"},
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_EmptyRules(t *testing.T) {
	// Rules with empty hostname or endpoint should be skipped
	ing := ParseIngress(&config.IngressConfig{
		Name: "partial-ing",
		Rules: []*config.IngressRuleConfig{
			{Hostname: "", Endpoint: "nope:8080"},  // skipped
			{Hostname: "nope.com", Endpoint: ""},    // skipped
			{Hostname: "valid.com", Endpoint: "10.0.0.1:8080"}, // kept
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress even with partial rules")
	}
}

func TestParseIngress_FileLoader(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "file-ing",
		File: &config.FileLoader{Path: "/tmp/ingress.txt"},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_HTTPLoader(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "http-ing",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/ingress"},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_RedisLoader(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "redis-ing",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "ingress-key",
			Type: "hash",
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}

func TestParseIngress_RedisSetLoader(t *testing.T) {
	ing := ParseIngress(&config.IngressConfig{
		Name: "redis-set-ing",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "ingress-set",
			Type: "set",
		},
	})
	if ing == nil {
		t.Fatal("expected non-nil ingress")
	}
}
