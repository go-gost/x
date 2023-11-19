package logger

import (
	"io"
	"os"
	"path/filepath"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
	"gopkg.in/natefinch/lumberjack.v2"
)

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
		return xlogger.Nop()
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
			os.MkdirAll(filepath.Dir(cfg.Log.Output), 0755)
			f, err := os.OpenFile(cfg.Log.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				logger.Default().Warn(err)
			} else {
				out = f
			}
		}
	}
	opts = append(opts, xlogger.OutputOption(out))

	return xlogger.NewLogger(opts...)
}
