package logger

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
)

// probeEnv marks the child process TestParseLogger_UnopenableOutput spawns:
// that test needs a process in which no default logger was ever installed,
// which is the state the failure path used to dereference.
const probeEnv = "X_LOGGER_UNOPENABLE_PROBE"

func TestMain(m *testing.M) {
	if os.Getenv(probeEnv) != "1" {
		logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))
	}
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

// TestParseLogger_UnopenableOutput: a log file that cannot be opened must leave
// the process logging somewhere, not panic. The failure used to be reported
// through logger.Default(), which is nil until a caller installs one — and this
// call is usually the one doing the installing — so an unwritable path (an app
// whose working directory is not writable, a typo'd directory) dereferenced a
// nil logger and took the whole process down.
//
// The state that matters is process-wide and TestMain sets it for every other
// case here, so the assertion runs in a child process: a fresh one is the only
// place the default logger is still unset, exactly as it is at startup.
func TestParseLogger_UnopenableOutput(t *testing.T) {
	if os.Getenv(probeEnv) == "1" {
		lg := ParseLogger(&config.LoggerConfig{Log: &config.LogConfig{
			Output: "/nonexistent-dir-for-test/wisper.log",
			Level:  "info",
		}})
		if lg == nil {
			fmt.Fprintln(os.Stderr, "ParseLogger returned nil for an unopenable output")
			os.Exit(1)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseLogger_UnopenableOutput", "-test.v")
	cmd.Env = append(os.Environ(), probeEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("a log file that cannot be opened must not be fatal:\n%s", out)
	}
}
