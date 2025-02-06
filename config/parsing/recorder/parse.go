package recorder

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/plugin"
	xrecorder "github.com/go-gost/x/recorder"
	recorder_plugin "github.com/go-gost/x/recorder/plugin"
	"gopkg.in/natefinch/lumberjack.v2"
)

type discardCloser struct{}

func (discardCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (discardCloser) Close() error                      { return nil }

func ParseRecorder(cfg *config.RecorderConfig) (r recorder.Recorder) {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		var tlsCfg *tls.Config
		if cfg.Plugin.TLS != nil {
			tlsCfg = &tls.Config{
				ServerName:         cfg.Plugin.TLS.ServerName,
				InsecureSkipVerify: !cfg.Plugin.TLS.Secure,
			}
		}
		switch strings.ToLower(cfg.Plugin.Type) {
		case "http":
			return recorder_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		default:
			return recorder_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			)
		}
	}

	if cfg.File != nil && cfg.File.Path != "" {
		var out io.WriteCloser = discardCloser{}

		if cfg.File.Rotation != nil {
			out = &lumberjack.Logger{
				Filename:   cfg.File.Path,
				MaxSize:    cfg.File.Rotation.MaxSize,
				MaxAge:     cfg.File.Rotation.MaxAge,
				MaxBackups: cfg.File.Rotation.MaxBackups,
				LocalTime:  cfg.File.Rotation.LocalTime,
				Compress:   cfg.File.Rotation.Compress,
			}
		} else {
			os.MkdirAll(filepath.Dir(cfg.File.Path), 0755)
			f, err := os.OpenFile(cfg.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				logger.Default().Warn(err)
			} else {
				out = f
			}
		}

		return xrecorder.FileRecorder(out, xrecorder.SepRecorderOption(cfg.File.Sep))
	}

	if cfg.TCP != nil && cfg.TCP.Addr != "" {
		return xrecorder.TCPRecorder(cfg.TCP.Addr, xrecorder.TimeoutTCPRecorderOption(cfg.TCP.Timeout))
	}

	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		h := http.Header{}
		for k, v := range cfg.HTTP.Header {
			h.Add(k, v)
		}
		return xrecorder.HTTPRecorder(cfg.HTTP.URL,
			xrecorder.TimeoutHTTPRecorderOption(cfg.HTTP.Timeout),
			xrecorder.HeaderHTTPRecorderOption(h),
		)
	}

	if cfg.Redis != nil &&
		cfg.Redis.Addr != "" &&
		cfg.Redis.Key != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			return xrecorder.RedisListRecorder(cfg.Redis.Addr,
				xrecorder.DBRedisRecorderOption(cfg.Redis.DB),
				xrecorder.KeyRedisRecorderOption(cfg.Redis.Key),
				xrecorder.UsernameRedisRecorderOption(cfg.Redis.Username),
				xrecorder.PasswordRedisRecorderOption(cfg.Redis.Password),
			)
		case "sset": // sorted set
			return xrecorder.RedisSortedSetRecorder(cfg.Redis.Addr,
				xrecorder.DBRedisRecorderOption(cfg.Redis.DB),
				xrecorder.KeyRedisRecorderOption(cfg.Redis.Key),
				xrecorder.UsernameRedisRecorderOption(cfg.Redis.Username),
				xrecorder.PasswordRedisRecorderOption(cfg.Redis.Password),
			)
		default: // redis set
			return xrecorder.RedisSetRecorder(cfg.Redis.Addr,
				xrecorder.DBRedisRecorderOption(cfg.Redis.DB),
				xrecorder.KeyRedisRecorderOption(cfg.Redis.Key),
				xrecorder.UsernameRedisRecorderOption(cfg.Redis.Username),
				xrecorder.PasswordRedisRecorderOption(cfg.Redis.Password),
			)
		}
	}

	return
}
