package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/registry"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ParseLogger converts a LoggerConfig into a logger.Logger. It configures
// output destination (stderr, stdout, file, or discard), log level, format,
// and optional log rotation via lumberjack.
func ParseLogger(cfg *config.LoggerConfig) logger.Logger {
	if cfg == nil || cfg.Log == nil {
		return nil
	}
	opts := []xlogger.Option{
		xlogger.NameOption(cfg.Name),
		xlogger.FormatOption(logger.LogFormat(cfg.Log.Format)),
		xlogger.LevelOption(logger.LogLevel(cfg.Log.Level)),
	}

	var out io.Writer = os.Stderr
	switch cfg.Log.Output {
	case "none", "null":
		out = io.Discard
	case "stdout":
		out = os.Stdout
	case "stderr", "":
		out = os.Stderr
	default:
		if cfg.Log.Rotation != nil {
			out = &lumberjack.Logger{
				Filename:   cfg.Log.Output,
				MaxSize:    cfg.Log.Rotation.MaxSize,
				MaxAge:     cfg.Log.Rotation.MaxAge,
				MaxBackups: cfg.Log.Rotation.MaxBackups,
				LocalTime:  cfg.Log.Rotation.LocalTime,
				Compress:   cfg.Log.Rotation.Compress,
			}
		} else {
			// Nothing rotates this file, and it is the only place that sees both
			// the path and the missing rotation — the default (an unconfigured
			// logger) always carries one.
			fmt.Fprintf(os.Stderr, "logger: %s has no rotation configured: it will grow without bound\n", cfg.Log.Output)
			os.MkdirAll(filepath.Dir(cfg.Log.Output), 0755)
			f, err := os.OpenFile(cfg.Log.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				// Reported on stderr, not through logger.Default(): that logger
				// is what this call is on its way to installing and is nil until
				// it is — calling a method on it panics, which aborted the whole
				// process on a log path that could not be opened (an app whose
				// working directory is not writable, say). A log file that
				// cannot be opened leaves the default output in place instead.
				fmt.Fprintf(os.Stderr, "logger: open %s: %v (logging to stderr)\n", cfg.Log.Output, err)
			} else {
				out = f
			}
		}
	}
	opts = append(opts, xlogger.OutputOption(out))

	return xlogger.NewLogger(opts...)
}

// List resolves one or more logger names from the registry. It returns only
// the loggers that were found, skipping any that are not registered.
func List(name string, names ...string) []logger.Logger {
	var loggers []logger.Logger
	if adm := registry.LoggerRegistry().Get(name); adm != nil {
		loggers = append(loggers, adm)
	}
	for _, s := range names {
		if lg := registry.LoggerRegistry().Get(s); lg != nil {
			loggers = append(loggers, lg)
		}
	}

	return loggers
}
