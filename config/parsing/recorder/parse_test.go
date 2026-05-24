package recorder

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

func TestParseRecorder_Nil(t *testing.T) {
	r := ParseRecorder(nil)
	if r != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseRecorder_PluginHTTP(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "http-rec",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder")
	}
}

func TestParseRecorder_PluginGRPC(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "grpc-rec",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "recorder.local",
			},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder")
	}
}

func TestParseRecorder_PluginDefaultType(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "default-rec",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder")
	}
}

func TestParseRecorder_TCP(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "tcp-rec",
		TCP: &config.TCPRecorder{
			Addr:    "127.0.0.1:9999",
			Timeout: 0,
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for TCP")
	}
}

func TestParseRecorder_HTTP(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "http-rec",
		HTTP: &config.HTTPRecorder{
			URL:     "http://localhost:8080/record",
			Timeout: 0,
			Header:  map[string]string{"X-Test": "value"},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for HTTP")
	}
}

func TestParseRecorder_File(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "file-rec",
		File: &config.FileRecorder{
			Path: "/tmp/recorder.log",
			Sep:  "\n",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for file")
	}
}

func TestParseRecorder_FileWithRotation(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "file-rot-rec",
		File: &config.FileRecorder{
			Path: "/tmp/recorder-rot.log",
			Rotation: &config.LogRotationConfig{
				MaxSize:    100,
				MaxAge:     30,
				MaxBackups: 10,
				LocalTime:  true,
				Compress:   true,
			},
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for file with rotation")
	}
}

func TestParseRecorder_RedisSet(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "redis-set-rec",
		Redis: &config.RedisRecorder{
			Addr: "127.0.0.1:6379",
			Key:  "recorder-set",
			Type: "set",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for redis set")
	}
}

func TestParseRecorder_RedisList(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "redis-list-rec",
		Redis: &config.RedisRecorder{
			Addr: "127.0.0.1:6379",
			Key:  "recorder-list",
			Type: "list",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for redis list")
	}
}

func TestParseRecorder_RedisSortedSet(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "redis-sset-rec",
		Redis: &config.RedisRecorder{
			Addr: "127.0.0.1:6379",
			Key:  "recorder-sset",
			Type: "sset",
		},
	})
	if r == nil {
		t.Fatal("expected non-nil recorder for redis sorted set")
	}
}

func TestParseRecorder_EmptyFileReturnsNil(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "empty-rec",
	})
	if r != nil {
		t.Fatal("expected nil recorder when no sub-config is provided")
	}
}

func TestParseRecorder_FileWithEmptyPathReturnsNil(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "empty-path-rec",
		File: &config.FileRecorder{
			Path: "",
		},
	})
	if r != nil {
		t.Fatal("expected nil recorder when file path is empty")
	}
}

func TestParseRecorder_TCPWithEmptyAddrReturnsNil(t *testing.T) {
	r := ParseRecorder(&config.RecorderConfig{
		Name: "empty-tcp-rec",
		TCP: &config.TCPRecorder{
			Addr: "",
		},
	})
	if r != nil {
		t.Fatal("expected nil recorder when TCP addr is empty")
	}
}
