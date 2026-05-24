package sd

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

func TestParseSD_Nil(t *testing.T) {
	s := ParseSD(nil)
	if s != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseSD_NilPlugin(t *testing.T) {
	s := ParseSD(&config.SDConfig{
		Name:   "no-plugin",
		Plugin: nil,
	})
	if s != nil {
		t.Fatal("expected nil when plugin is nil")
	}
}

func TestParseSD_PluginHTTP(t *testing.T) {
	s := ParseSD(&config.SDConfig{
		Name: "http-sd",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if s == nil {
		t.Fatal("expected non-nil SD")
	}
}

func TestParseSD_PluginGRPC(t *testing.T) {
	s := ParseSD(&config.SDConfig{
		Name: "grpc-sd",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "sd.local",
			},
		},
	})
	if s == nil {
		t.Fatal("expected non-nil SD")
	}
}

func TestParseSD_PluginDefaultType(t *testing.T) {
	s := ParseSD(&config.SDConfig{
		Name: "default-sd",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if s == nil {
		t.Fatal("expected non-nil SD")
	}
}
