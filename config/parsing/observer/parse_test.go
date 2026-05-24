package observer

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

func TestParseObserver_Nil(t *testing.T) {
	obs := ParseObserver(nil)
	if obs != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseObserver_NilPlugin(t *testing.T) {
	obs := ParseObserver(&config.ObserverConfig{
		Name:   "no-plugin",
		Plugin: nil,
	})
	if obs != nil {
		t.Fatal("expected nil when plugin is nil")
	}
}

func TestParseObserver_PluginHTTP(t *testing.T) {
	obs := ParseObserver(&config.ObserverConfig{
		Name: "http-obs",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if obs == nil {
		t.Fatal("expected non-nil observer")
	}
}

func TestParseObserver_PluginGRPC(t *testing.T) {
	obs := ParseObserver(&config.ObserverConfig{
		Name: "grpc-obs",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "observer.local",
			},
		},
	})
	if obs == nil {
		t.Fatal("expected non-nil observer")
	}
}

func TestParseObserver_PluginDefaultType(t *testing.T) {
	obs := ParseObserver(&config.ObserverConfig{
		Name: "default-obs",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if obs == nil {
		t.Fatal("expected non-nil observer")
	}
}
