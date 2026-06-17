package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-gost/core/logger"
)

// Custom slog levels to cover the full logrus-compatible range.
// slog built-in: Debug=-4, Info=0, Warn=4, Error=8.
const (
	levelTrace slog.Level = -8
	levelFatal slog.Level = 12
)

// Options holds the configuration for a logger.
type Options struct {
	Name   string
	Output io.Writer
	Format logger.LogFormat
	Level  logger.LogLevel
}

// Option is a functional option for configuring a logger.
type Option func(opts *Options)

// NameOption sets the logger name. When set, every log entry carries a
// "logger" field with this value.
func NameOption(name string) Option {
	return func(opts *Options) {
		opts.Name = name
	}
}

// OutputOption sets the output destination. Defaults to os.Stderr.
func OutputOption(out io.Writer) Option {
	return func(opts *Options) {
		opts.Output = out
	}
}

// FormatOption sets the log format (TextFormat or JSONFormat). Defaults to JSON.
func FormatOption(format logger.LogFormat) Option {
	return func(opts *Options) {
		opts.Format = format
	}
}

// LevelOption sets the minimum log level. Defaults to InfoLevel.
func LevelOption(level logger.LogLevel) Option {
	return func(opts *Options) {
		opts.Level = level
	}
}

// slogLogger implements logger.Logger backed by log/slog.
type slogLogger struct {
	logger *slog.Logger
	level  *slog.LevelVar
}

// NewLogger creates a new logger.Logger backed by log/slog.
// The returned logger implements the core/logger.Logger interface.
func NewLogger(opts ...Option) logger.Logger {
	var options Options
	for _, opt := range opts {
		opt(&options)
	}

	out := options.Output
	if out == nil {
		out = os.Stderr
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(convertLevel(options.Level))

	handler := newHandler(out, levelVar, options.Format)

	sl := slog.New(handler)
	if options.Name != "" {
		sl = sl.With("logger", options.Name)
	}

	return &slogLogger{
		logger: sl,
		level:  levelVar,
	}
}

// newHandler creates the appropriate slog.Handler based on the format.
func newHandler(w io.Writer, levelVar *slog.LevelVar, format logger.LogFormat) slog.Handler {
	ho := &slog.HandlerOptions{
		Level:       levelVar,
		ReplaceAttr: replaceAttr,
	}
	switch format {
	case logger.TextFormat:
		return slog.NewTextHandler(w, ho)
	default:
		return slog.NewJSONHandler(w, ho)
	}
}

// replaceAttr normalises slog output to match the logrus format:
//   - level names are lowercased (info, debug, warn, error, fatal, trace)
//   - timestamps use RFC 3339 with milliseconds and numeric timezone offset
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		if t, ok := a.Value.Any().(time.Time); ok {
			a.Value = slog.StringValue(t.Format("2006-01-02T15:04:05.000Z07:00"))
		}
	case slog.LevelKey:
		if level, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(levelString(level))
		}
	}
	return a
}

// levelString returns a logrus-style lowercase level name for the given slog level.
func levelString(level slog.Level) string {
	switch {
	case level <= levelTrace:
		return "trace"
	case level <= slog.LevelDebug:
		return "debug"
	case level <= slog.LevelInfo:
		return "info"
	case level <= slog.LevelWarn:
		return "warn"
	case level <= slog.LevelError:
		return "error"
	default:
		return "fatal"
	}
}

// convertLevel maps a core logger.LogLevel to the corresponding slog.Level.
func convertLevel(lvl logger.LogLevel) slog.Level {
	switch lvl {
	case logger.TraceLevel:
		return levelTrace
	case logger.DebugLevel:
		return slog.LevelDebug
	case logger.InfoLevel:
		return slog.LevelInfo
	case logger.WarnLevel:
		return slog.LevelWarn
	case logger.ErrorLevel:
		return slog.LevelError
	case logger.FatalLevel:
		return levelFatal
	default:
		return slog.LevelInfo
	}
}

// revertLevel maps a slog.Level back to a core logger.LogLevel.
func revertLevel(lvl slog.Level) logger.LogLevel {
	switch {
	case lvl <= levelTrace:
		return logger.TraceLevel
	case lvl <= slog.LevelDebug:
		return logger.DebugLevel
	case lvl <= slog.LevelInfo:
		return logger.InfoLevel
	case lvl <= slog.LevelWarn:
		return logger.WarnLevel
	case lvl <= slog.LevelError:
		return logger.ErrorLevel
	default:
		return logger.FatalLevel
	}
}

// WithFields returns a new Logger with the given fields attached to every
// subsequent log entry.
func (l *slogLogger) WithFields(fields map[string]any) logger.Logger {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}
	return &slogLogger{
		logger: l.logger.With(attrs...),
		level:  l.level,
	}
}

// Trace logs at Trace level.
func (l *slogLogger) Trace(args ...any) {
	l.log(levelTrace, args...)
}

// Tracef logs a formatted message at Trace level.
func (l *slogLogger) Tracef(format string, args ...any) {
	l.logf(levelTrace, format, args...)
}

// Debug logs at Debug level.
func (l *slogLogger) Debug(args ...any) {
	l.log(slog.LevelDebug, args...)
}

// Debugf logs a formatted message at Debug level.
func (l *slogLogger) Debugf(format string, args ...any) {
	l.logf(slog.LevelDebug, format, args...)
}

// Info logs at Info level.
func (l *slogLogger) Info(args ...any) {
	l.log(slog.LevelInfo, args...)
}

// Infof logs a formatted message at Info level.
func (l *slogLogger) Infof(format string, args ...any) {
	l.logf(slog.LevelInfo, format, args...)
}

// Warn logs at Warn level.
func (l *slogLogger) Warn(args ...any) {
	l.log(slog.LevelWarn, args...)
}

// Warnf logs a formatted message at Warn level.
func (l *slogLogger) Warnf(format string, args ...any) {
	l.logf(slog.LevelWarn, format, args...)
}

// Error logs at Error level.
func (l *slogLogger) Error(args ...any) {
	l.log(slog.LevelError, args...)
}

// Errorf logs a formatted message at Error level.
func (l *slogLogger) Errorf(format string, args ...any) {
	l.logf(slog.LevelError, format, args...)
}

// Fatal logs at Fatal level and then calls os.Exit(1).
func (l *slogLogger) Fatal(args ...any) {
	l.log(levelFatal, args...)
	os.Exit(1)
}

// Fatalf logs a formatted message at Fatal level and then calls os.Exit(1).
func (l *slogLogger) Fatalf(format string, args ...any) {
	l.logf(levelFatal, format, args...)
	os.Exit(1)
}

// GetLevel returns the current log level.
func (l *slogLogger) GetLevel() logger.LogLevel {
	return revertLevel(l.level.Level())
}

// IsLevelEnabled reports whether messages at the given level will be logged.
func (l *slogLogger) IsLevelEnabled(level logger.LogLevel) bool {
	return l.level.Level() <= convertLevel(level)
}

// log emits a log entry. When the configured level is Debug or lower it
// attaches a "caller" field with the source file and line.
//
// Stack depth assumption for the skip=3 argument to caller:
//
//	0: runtime.Caller
//	1: caller
//	2: log (this method)
//	3: level method (Trace, Debug, Info, etc.)
//	4: user's call site
func (l *slogLogger) log(level slog.Level, args ...any) {
	if l.level.Level() > level {
		return
	}
	msg := fmt.Sprint(args...)
	if l.level.Level() <= slog.LevelDebug {
		l.logger.LogAttrs(context.Background(), level, msg,
			slog.String("caller", l.caller(3)))
	} else {
		l.logger.LogAttrs(context.Background(), level, msg)
	}
}

// logf emits a formatted log entry. When the configured level is Debug or
// lower it attaches a "caller" field with the source file and line.
func (l *slogLogger) logf(level slog.Level, format string, args ...any) {
	if l.level.Level() > level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if l.level.Level() <= slog.LevelDebug {
		l.logger.LogAttrs(context.Background(), level, msg,
			slog.String("caller", l.caller(3)))
	} else {
		l.logger.LogAttrs(context.Background(), level, msg)
	}
}

// caller returns a "dir/file.go:line" description of the caller, skipping
// the given number of stack frames.
func (l *slogLogger) caller(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		file = "<???>"
	} else {
		file = filepath.Join(filepath.Base(filepath.Dir(file)), filepath.Base(file))
	}
	return fmt.Sprintf("%s:%d", file, line)
}
