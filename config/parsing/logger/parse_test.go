package logger

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
	"gopkg.in/natefinch/lumberjack.v2"
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

// TestParseLoggerUnrotatedFileRotates is the defect that filled a phone's
// storage. A log: section without a rotation: key used to get a plain
// *os.File — nothing rotates it — and one debug-level spoke grew it to 111MB
// with no backups, which on a phone is not untidy so much as fatal.
//
// The default rotation is what the unconfigured logger already carries, so
// naming one should not be a way to opt out of it.
func TestParseLoggerUnrotatedFileRotates(t *testing.T) {
	file := filepath.Join(t.TempDir(), "wisper.log")
	cfg := &config.LoggerConfig{
		Log: &config.LogConfig{
			Output: file,
			Level:  "debug",
			Format: "json",
			// Rotation deliberately absent: the shape wisper.yaml on Android has.
		},
	}

	w := outputWriter(cfg.Log)
	if w == nil {
		t.Fatal("outputWriter = nil")
	}
	if _, ok := w.(*lumberjack.Logger); !ok {
		t.Fatalf("outputWriter = %T, want a *lumberjack.Logger so the file rotates", w)
	}

	lg := w.(*lumberjack.Logger)
	if lg.Filename != file {
		t.Errorf("Filename = %q, want %q", lg.Filename, file)
	}
	if lg.MaxSize <= 0 || lg.MaxBackups <= 0 {
		t.Errorf("rotation is off: MaxSize=%d MaxBackups=%d, want both positive", lg.MaxSize, lg.MaxBackups)
	}
}

// TestParseLoggerExplicitRotationWins: a configured rotation is respected as
// written, so the default is only a floor for what was left out.
func TestParseLoggerExplicitRotationWins(t *testing.T) {
	file := filepath.Join(t.TempDir(), "wisper.log")
	cfg := &config.LoggerConfig{
		Log: &config.LogConfig{
			Output: file,
			Rotation: &config.LogRotationConfig{
				MaxSize:    33,
				MaxBackups: 5,
			},
		},
	}

	lg, ok := outputWriter(cfg.Log).(*lumberjack.Logger)
	if !ok {
		t.Fatalf("outputWriter = %T, want *lumberjack.Logger", outputWriter(cfg.Log))
	}
	if lg.MaxSize != 33 || lg.MaxBackups != 5 {
		t.Errorf("MaxSize=%d MaxBackups=%d, want 33 and 5 as configured", lg.MaxSize, lg.MaxBackups)
	}
}

// TestParseLoggerNotAFileStillGoesToTheSink: stderr/stdout/none are unaffected,
// so defaulting the rotation cannot leak a file into a stream.
func TestParseLoggerNotAFileStillGoesToTheSink(t *testing.T) {
	for _, out := range []string{"stderr", "stdout", "none", ""} {
		w := outputWriter(&config.LogConfig{Output: out})
		switch out {
		case "none":
			if w != io.Discard {
				t.Errorf("none: writer = %T, want io.Discard", w)
			}
		case "stdout":
			if w != os.Stdout {
				t.Errorf("stdout: writer = %T, want os.Stdout", w)
			}
		default:
			if w != os.Stderr {
				t.Errorf("%q: writer = %T, want os.Stderr", out, w)
			}
		}
	}
}
