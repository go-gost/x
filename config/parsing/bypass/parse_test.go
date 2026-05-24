package bypass

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

func TestParseBypass_Nil(t *testing.T) {
	bp := ParseBypass(nil)
	if bp != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseBypass_PluginHTTP(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name: "http-bp",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_PluginGRPC(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name: "grpc-bp",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "bypass.local",
			},
		},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_PluginDefaultType(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name: "default-bp",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_WithMatchers(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name:     "matcher-bp",
		Matchers: []string{"127.0.0.1", "10.0.0.0/8", "*.example.com"},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_Whitelist(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name:      "whitelist-bp",
		Whitelist: true,
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_Reverse(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name:    "reverse-bp",
		Reverse: true,
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_FileLoader(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name: "file-bp",
		File: &config.FileLoader{Path: "/tmp/bypass.txt"},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_HTTPLoader(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name: "http-bp",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/list"},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestParseBypass_RedisLoader(t *testing.T) {
	bp := ParseBypass(&config.BypassConfig{
		Name: "redis-bp",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "bypass-set",
		},
	})
	if bp == nil {
		t.Fatal("expected non-nil bypass")
	}
}

func TestList_ReturnsEntries(t *testing.T) {
	// The registry returns a lazy wrapper for any non-empty name.
	got := List("test-bypass", "test-bypass-2")
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestList_EmptyNameReturnsNothing(t *testing.T) {
	// Empty names are filtered by the registry Get.
	got := List("")
	if len(got) != 0 {
		t.Fatal("expected empty list for empty name")
	}
}
