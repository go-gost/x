package tunnel

import (
	"os"
	"testing"

	"github.com/go-gost/core/logger"
)

// TestMain sets up a non-nil default logger for all tests in this package.
func TestMain(m *testing.M) {
	logger.SetDefault(nopLogger{})
	os.Exit(m.Run())
}

type nopLogger struct {
	logger.Logger
}

func (nopLogger) Debugf(format string, args ...any) {}
func (nopLogger) Infof(format string, args ...any)  {}
func (nopLogger) Warnf(format string, args ...any)  {}
func (nopLogger) Errorf(format string, args ...any) {}
func (nopLogger) Tracef(format string, args ...any) {}
func (nopLogger) Debug(args ...any)                 {}
func (nopLogger) Info(args ...any)                  {}
func (nopLogger) Warn(args ...any)                  {}
func (nopLogger) Error(args ...any)                 {}
func (nopLogger) Trace(args ...any)                 {}
func (nopLogger) Fatal(args ...any)                 {}
func (nopLogger) Fatalf(format string, args ...any) {}
func (nopLogger) GetLevel() logger.LogLevel         { return logger.ErrorLevel }
func (nopLogger) IsLevelEnabled(level logger.LogLevel) bool { return false }
func (nopLogger) WithFields(fields map[string]any) logger.Logger { return nopLogger{} }

// testLogger returns a non-nil Logger usable in tests.
func testLogger() logger.Logger { return nopLogger{} }