package logger

import (
	"io"
	"os"

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

	opts = append(opts, xlogger.OutputOption(outputWriter(cfg.Log)))

	return xlogger.NewLogger(opts...)
}

// defaultLogRotation is what a file log gets when its config leaves the
// rotation out. It matches what an unconfigured logger has always carried, so
// a log: section that names an output but no rotation is not a way to ask for
// an unbounded file.
//
// The reason this is a default rather than a warning: an unrotated debug log
// is not untidy, it stops the device. A spoke's log section with no rotation:
// key grew to 111MB with no backups, on a phone.
func defaultLogRotation() *config.LogRotationConfig {
	return &config.LogRotationConfig{
		MaxSize:    10,
		MaxAge:     7,
		MaxBackups: 10,
		LocalTime:  true,
	}
}

// outputWriter resolves the LogConfig's output to the writer that receives the
// lines. Split out of ParseLogger so the rotation decision — the part that
// decides whether a file log stops growing — is reachable without a logger.
func outputWriter(cfg *config.LogConfig) io.Writer {
	var out io.Writer = os.Stderr
	switch cfg.Output {
	case "none", "null":
		out = io.Discard
	case "stdout":
		out = os.Stdout
	case "stderr", "":
		out = os.Stderr
	default:
		if cfg.Rotation == nil {
			cfg.Rotation = defaultLogRotation()
		}
		out = &lumberjack.Logger{
			Filename:   cfg.Output,
			MaxSize:    cfg.Rotation.MaxSize,
			MaxAge:     cfg.Rotation.MaxAge,
			MaxBackups: cfg.Rotation.MaxBackups,
			LocalTime:  cfg.Rotation.LocalTime,
			Compress:   cfg.Rotation.Compress,
		}
	}
	return out
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
