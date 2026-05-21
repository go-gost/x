package dialer

import (
	"os"
	"testing"

	"github.com/go-gost/core/logger"
)

type nopLogger struct{}

func (l *nopLogger) WithFields(map[string]any) logger.Logger      { return l }
func (l *nopLogger) Trace(args ...any)                             {}
func (l *nopLogger) Tracef(format string, args ...any)             {}
func (l *nopLogger) Debug(args ...any)                             {}
func (l *nopLogger) Debugf(format string, args ...any)             {}
func (l *nopLogger) Info(args ...any)                              {}
func (l *nopLogger) Infof(format string, args ...any)              {}
func (l *nopLogger) Warn(args ...any)                              {}
func (l *nopLogger) Warnf(format string, args ...any)              {}
func (l *nopLogger) Error(args ...any)                             {}
func (l *nopLogger) Errorf(format string, args ...any)             {}
func (l *nopLogger) Fatal(args ...any)                             {}
func (l *nopLogger) Fatalf(format string, args ...any)             {}
func (l *nopLogger) GetLevel() logger.LogLevel                     { return logger.InfoLevel }
func (l *nopLogger) IsLevelEnabled(level logger.LogLevel) bool     { return false }

func TestMain(m *testing.M) {
	logger.SetDefault(&nopLogger{})
	os.Exit(m.Run())
}
