package hosts

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

func TestParseHostMapper_Nil(t *testing.T) {
	hm := ParseHostMapper(nil)
	if hm != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseHostMapper_PluginHTTP(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "http-hosts",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_PluginGRPC(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "grpc-hosts",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "hosts.local",
			},
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_PluginDefaultType(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "default-hosts",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_WithMappings(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "mapping-hosts",
		Mappings: []*config.HostMappingConfig{
			{IP: "127.0.0.1", Hostname: "localhost"},
			{IP: "::1", Hostname: "ipv6-localhost"},
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_EmptyMapping(t *testing.T) {
	// Mappings with empty IP or Hostname should be skipped
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "partial-hosts",
		Mappings: []*config.HostMappingConfig{
			{IP: "", Hostname: "nope"},      // skipped
			{IP: "127.0.0.1", Hostname: ""}, // skipped
			{IP: "127.0.0.1", Hostname: "valid"}, // kept
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper even with partial mappings")
	}
}

func TestParseHostMapper_InvalidIP(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "invalid-ip",
		Mappings: []*config.HostMappingConfig{
			{IP: "not-an-ip", Hostname: "example.com"}, // skipped
			{IP: "127.0.0.1", Hostname: "valid"},       // kept
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper even with invalid IP")
	}
}

func TestParseHostMapper_FileLoader(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "file-hosts",
		File: &config.FileLoader{Path: "/etc/hosts"},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_HTTPLoader(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "http-hosts",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/hosts"},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_RedisLoader(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "redis-hosts",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "hosts-key",
			Type: "set",
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}

func TestParseHostMapper_RedisListLoader(t *testing.T) {
	hm := ParseHostMapper(&config.HostsConfig{
		Name: "redis-list-hosts",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "hosts-list",
			Type: "list",
		},
	})
	if hm == nil {
		t.Fatal("expected non-nil host mapper")
	}
}
