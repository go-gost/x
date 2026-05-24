package limiter

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

func TestParseTrafficLimiter_Nil(t *testing.T) {
	lim := ParseTrafficLimiter(nil)
	if lim != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseTrafficLimiter_WithLimits(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name:   "traffic-limiter",
		Limits: []string{"100KB", "200KB"},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_PluginHTTP(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "http-lim",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_PluginGRPC(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "grpc-lim",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "limiter.local",
			},
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_PluginDefaultType(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "default-lim",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_FileLoader(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "file-lim",
		File: &config.FileLoader{Path: "/tmp/limiter.txt"},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_HTTPLoader(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "http-lim",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/limits"},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_RedisLoader(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "redis-lim",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "limiter-key",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

func TestParseTrafficLimiter_RedisListLoader(t *testing.T) {
	lim := ParseTrafficLimiter(&config.LimiterConfig{
		Name: "redis-list-lim",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "limiter-list",
			Type: "list",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil traffic limiter")
	}
}

// --- ConnLimiter ---

func TestParseConnLimiter_Nil(t *testing.T) {
	lim := ParseConnLimiter(nil)
	if lim != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseConnLimiter_WithLimits(t *testing.T) {
	lim := ParseConnLimiter(&config.LimiterConfig{
		Name:   "conn-limiter",
		Limits: []string{"10", "50"},
	})
	if lim == nil {
		t.Fatal("expected non-nil conn limiter")
	}
}

func TestParseConnLimiter_RedisLoader(t *testing.T) {
	lim := ParseConnLimiter(&config.LimiterConfig{
		Name: "redis-conn-lim",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "conn-key",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil conn limiter")
	}
}

func TestParseConnLimiter_RedisListLoader(t *testing.T) {
	lim := ParseConnLimiter(&config.LimiterConfig{
		Name: "redis-list-conn-lim",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "conn-list",
			Type: "list",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil conn limiter")
	}
}

func TestParseConnLimiter_FileLoader(t *testing.T) {
	lim := ParseConnLimiter(&config.LimiterConfig{
		Name: "file-conn-lim",
		File: &config.FileLoader{Path: "/tmp/conn_limiter.txt"},
	})
	if lim == nil {
		t.Fatal("expected non-nil conn limiter")
	}
}

// --- RateLimiter ---

func TestParseRateLimiter_Nil(t *testing.T) {
	lim := ParseRateLimiter(nil)
	if lim != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseRateLimiter_WithLimits(t *testing.T) {
	lim := ParseRateLimiter(&config.LimiterConfig{
		Name:   "rate-limiter",
		Limits: []string{"100", "200"},
	})
	if lim == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

func TestParseRateLimiter_RedisLoader(t *testing.T) {
	lim := ParseRateLimiter(&config.LimiterConfig{
		Name: "redis-rate-lim",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "rate-key",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

func TestParseRateLimiter_RedisListLoader(t *testing.T) {
	lim := ParseRateLimiter(&config.LimiterConfig{
		Name: "redis-list-rate-lim",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "rate-list",
			Type: "list",
		},
	})
	if lim == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

func TestParseRateLimiter_FileLoader(t *testing.T) {
	lim := ParseRateLimiter(&config.LimiterConfig{
		Name: "file-rate-lim",
		File: &config.FileLoader{Path: "/tmp/rate_limiter.txt"},
	})
	if lim == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}
