package logger

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

func TestParseLogger_Nil(t *testing.T) {
	lg := ParseLogger(nil)
	if lg != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseLogger_NilLog(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "test",
		Log:  nil,
	})
	if lg != nil {
		t.Fatal("expected nil when Log is nil")
	}
}

func TestParseLogger_Levels(t *testing.T) {
	for _, level := range []string{"trace", "debug", "info", "warn", "error", "fatal"} {
		t.Run(level, func(t *testing.T) {
			lg := ParseLogger(&config.LoggerConfig{
				Name: "test-" + level,
				Log: &config.LogConfig{
					Level: level,
				},
			})
			if lg == nil {
				t.Fatal("expected non-nil logger")
			}
		})
	}
}

func TestParseLogger_OutputNone(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "null-logger",
		Log: &config.LogConfig{
			Output: "none",
		},
	})
	if lg == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestParseLogger_OutputStdout(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "stdout-logger",
		Log: &config.LogConfig{
			Output: "stdout",
		},
	})
	if lg == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestParseLogger_OutputStderr(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "stderr-logger",
		Log: &config.LogConfig{
			Output: "stderr",
		},
	})
	if lg == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestParseLogger_OutputDefault(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "default-logger",
		Log: &config.LogConfig{
			Output: "",
		},
	})
	if lg == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestParseLogger_WithFormat(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "format-logger",
		Log: &config.LogConfig{
			Format: "json",
			Level:  "info",
		},
	})
	if lg == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestParseLogger_FileOutput(t *testing.T) {
	lg := ParseLogger(&config.LoggerConfig{
		Name: "file-logger",
		Log: &config.LogConfig{
			Output: "/tmp/gost-test.log",
			Rotation: &config.LogRotationConfig{
				MaxSize:    10,
				MaxAge:     7,
				MaxBackups: 5,
				LocalTime:  true,
				Compress:   true,
			},
		},
	})
	if lg == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestList_EmptyLogger(t *testing.T) {
	got := List("nonexistent")
	if len(got) != 0 {
		t.Fatal("expected empty list for unregistered name")
	}
}

func TestList_WithNames(t *testing.T) {
	got := List("nonexistent", "also_nonexistent")
	if len(got) != 0 {
		t.Fatal("expected empty list for unregistered names")
	}
}
