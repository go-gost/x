package router

import (
	"context"
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

func TestParseRouter_Nil(t *testing.T) {
	r := ParseRouter(nil)
	if r != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseRouter_PluginHTTP(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "http-rt",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_PluginGRPC(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "grpc-rt",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "router.local",
			},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_PluginDefaultType(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "default-rt",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_WithCIDRRoutes(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "cidr-rt",
		Routes: []*config.RouterRouteConfig{
			{Net: "192.168.1.0/24", Gateway: "10.0.0.1"},
			{Net: "10.0.0.0/8", Gateway: "10.0.0.2"},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router with CIDR routes")
	}
}

func TestParseRouter_WithDstRoutes(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "dst-rt",
		Routes: []*config.RouterRouteConfig{
			{Dst: "192.168.1.0/24", Gateway: "10.0.0.1"},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router with dst routes")
	}
}

func TestParseRouter_MissingGatewaySkipped(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "skip-rt",
		Routes: []*config.RouterRouteConfig{
			{Net: "192.168.1.0/24", Gateway: ""},          // skipped: no gateway
			{Net: "10.0.0.0/8", Gateway: "10.0.0.1"},      // kept
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router (with one valid route)")
	}
}

func TestParseRouter_MissingDstSkipped(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "no-dst-rt",
		Routes: []*config.RouterRouteConfig{
			{Dst: "", Gateway: "10.0.0.1"}, // skipped: no dst
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router (all routes skipped)")
	}
}

func TestParseRouter_InvalidCIDRSkipped(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "invalid-cidr-rt",
		Routes: []*config.RouterRouteConfig{
			{Net: "not-a-cidr", Gateway: "10.0.0.1"},    // invalid CIDR with empty Dst, skipped
			{Net: "192.168.1.0/24", Gateway: "10.0.0.2"}, // valid
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_NilRouteSkipped(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "nil-route-rt",
		Routes: []*config.RouterRouteConfig{
			nil,
			{Net: "192.168.1.0/24", Gateway: "10.0.0.1"},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router when nil route is in list")
	}
}

func TestParseRouter_EmptyRoutes(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name:   "empty-routes",
		Routes: []*config.RouterRouteConfig{},
	})
	if r == nil {
		t.Fatal("expected non-nil router with empty routes")
	}
}

func TestParseRouter_FileLoader(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "file-rt",
		File: &config.FileLoader{Path: "/tmp/routes.txt"},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_HTTPLoader(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "http-rt",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/routes"},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_RedisHashLoader(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "redis-hash-rt",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "routes-hash",
			Type: "hash",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_RedisListLoader(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "redis-list-rt",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "routes-list",
			Type: "list",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_RedisSetLoader(t *testing.T) {
	r := ParseRouter(&config.RouterConfig{
		Name: "redis-set-rt",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "routes-set",
			Type: "set",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestParseRouter_DstSyncedFromNet(t *testing.T) {
	// When Dst is empty but Net is provided, Net is converted to Dst
	r := ParseRouter(&config.RouterConfig{
		Name: "net-to-dst-rt",
		Routes: []*config.RouterRouteConfig{
			{Net: "192.168.1.0/24", Gateway: "10.0.0.1"},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
	route := r.GetRoute(context.Background(), "192.168.1.5")
	if route == nil {
		t.Fatal("expected non-nil route for IP in CIDR range")
	}
	if route.Dst != "192.168.1.0/24" {
		t.Fatalf("Dst = %q, want %q", route.Dst, "192.168.1.0/24")
	}
	if route.Gateway != "10.0.0.1" {
		t.Fatalf("Gateway = %q, want %q", route.Gateway, "10.0.0.1")
	}
}
