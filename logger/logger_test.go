package logger

import (
	"bytes"
	"log/slog"
	"regexp"
	"testing"
	"time"

	"github.com/go-gost/core/logger"
)

func TestConvertLevelRevertLevelRoundTrip(t *testing.T) {
	levels := []logger.LogLevel{
		logger.TraceLevel,
		logger.DebugLevel,
		logger.InfoLevel,
		logger.WarnLevel,
		logger.ErrorLevel,
		logger.FatalLevel,
	}

	for _, lvl := range levels {
		slogLvl := convertLevel(lvl)
		back := revertLevel(slogLvl)
		if back != lvl {
			t.Errorf("round-trip failed for %q: got %q", lvl, back)
		}
	}
}

func TestConvertLevelDefault(t *testing.T) {
	if got := convertLevel("unknown"); got != slog.LevelInfo {
		t.Errorf("expected Info level for unknown input, got %v", got)
	}
}

func TestRevertLevelMapping(t *testing.T) {
	tests := []struct {
		slogLevel slog.Level
		want      logger.LogLevel
	}{
		{levelTrace, logger.TraceLevel},
		{levelTrace + 1, logger.DebugLevel},
		{slog.LevelDebug, logger.DebugLevel},
		{slog.LevelDebug + 1, logger.InfoLevel},
		{slog.LevelInfo, logger.InfoLevel},
		{slog.LevelInfo + 1, logger.WarnLevel},
		{slog.LevelWarn, logger.WarnLevel},
		{slog.LevelWarn + 1, logger.ErrorLevel},
		{slog.LevelError, logger.ErrorLevel},
		{slog.LevelError + 1, logger.FatalLevel},
		{levelFatal, logger.FatalLevel},
	}

	for _, tt := range tests {
		got := revertLevel(tt.slogLevel)
		if got != tt.want {
			t.Errorf("revertLevel(%v) = %q, want %q", tt.slogLevel, got, tt.want)
		}
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{levelTrace - 1, "trace"},
		{levelTrace, "trace"},
		{slog.LevelDebug, "debug"},
		{slog.LevelInfo, "info"},
		{slog.LevelWarn, "warn"},
		{slog.LevelError, "error"},
		{levelFatal, "fatal"},
		{levelFatal + 1, "fatal"},
	}

	for _, tt := range tests {
		got := levelString(tt.level)
		if got != tt.want {
			t.Errorf("levelString(%v) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestReplaceAttrTimestamp(t *testing.T) {
	ts := time.Date(2026, 6, 17, 12, 0, 0, 123000000, time.FixedZone("+0800", 8*60*60))
	attr := slog.Attr{Key: slog.TimeKey, Value: slog.TimeValue(ts)}

	result := replaceAttr(nil, attr)
	got := result.Value.String()

	// Should be RFC 3339 with milliseconds and numeric timezone: "2026-06-17T12:00:00.123+08:00"
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$`)
	if !re.MatchString(got) {
		t.Errorf("timestamp format mismatch: got %q", got)
	}
}

func TestReplaceAttrLevel(t *testing.T) {
	attr := slog.Attr{Key: slog.LevelKey, Value: slog.AnyValue(slog.LevelDebug)}
	result := replaceAttr(nil, attr)
	if got := result.Value.String(); got != "debug" {
		t.Errorf("expected level 'debug', got %q", got)
	}
}

func TestReplaceAttrNonMatchingKey(t *testing.T) {
	attr := slog.Attr{Key: "msg", Value: slog.StringValue("hello")}
	result := replaceAttr(nil, attr)
	if result.Value.String() != "hello" {
		t.Errorf("expected unchanged value 'hello', got %q", result.Value.String())
	}
}

func TestReplaceAttrWithGroups(t *testing.T) {
	// When groups are present, replaceAttr should pass through unchanged.
	attr := slog.Attr{Key: slog.LevelKey, Value: slog.AnyValue(slog.LevelWarn)}
	result := replaceAttr([]string{"sub"}, attr)
	if result.Value.Kind() != slog.KindAny {
		t.Errorf("expected unchanged level value kind, got %v", result.Value.Kind())
	}
}

func TestCallerFormat(t *testing.T) {
	l := &slogLogger{logger: slog.Default(), level: new(slog.LevelVar)}
	caller := l.caller(0)
	// skip=0 resolves to the caller function's own location (logger.go), not
	// the test file. Match the "dir/file.go:line" format.
	re := regexp.MustCompile(`^\w+/[^/]+\.go:\d+$`)
	if !re.MatchString(caller) {
		t.Errorf("caller format mismatch: got %q", caller)
	}
}

func TestLevelGuardSkipsFormatting(t *testing.T) {
	// Log with a level below the configured threshold — should be a no-op.
	var buf bytes.Buffer
	l := NewLogger(
		OutputOption(&buf),
		LevelOption(logger.WarnLevel),
		FormatOption(logger.TextFormat),
	)
	// Info is below Warn; message should not appear.
	l.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestLevelGuardAllowsHigherLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(
		OutputOption(&buf),
		LevelOption(logger.WarnLevel),
		FormatOption(logger.TextFormat),
	)
	// Error is above Warn; message should appear.
	l.Error("should appear")
	if buf.Len() == 0 {
		t.Error("expected output, got none")
	}
}

func TestWithFields(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(
		OutputOption(&buf),
		LevelOption(logger.InfoLevel),
		FormatOption(logger.TextFormat),
	)
	child := l.WithFields(map[string]any{"request_id": "abc123"})
	child.Info("test message")
	out := buf.String()
	if out == "" {
		t.Error("expected output, got none")
	}
	// Verify the child and parent share the same LevelVar.
	parentLevel := l.GetLevel()
	childLevel := child.GetLevel()
	if parentLevel != childLevel {
		t.Errorf("parent and child levels should match: %q vs %q", parentLevel, childLevel)
	}
}

func TestIsLevelEnabled(t *testing.T) {
	l := NewLogger(LevelOption(logger.InfoLevel))
	if !l.IsLevelEnabled(logger.WarnLevel) {
		t.Error("Warn should be enabled when level is Info")
	}
	if l.IsLevelEnabled(logger.TraceLevel) {
		t.Error("Trace should be disabled when level is Info")
	}
}

func TestGetLevel(t *testing.T) {
	l := NewLogger(LevelOption(logger.ErrorLevel))
	if got := l.GetLevel(); got != logger.ErrorLevel {
		t.Errorf("expected ErrorLevel, got %q", got)
	}
}
