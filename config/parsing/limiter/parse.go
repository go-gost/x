package limiter

import (
	"crypto/tls"
	"strings"

	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/plugin"
	xconn "github.com/go-gost/x/limiter/conn"
	xrate "github.com/go-gost/x/limiter/rate"
	xtraffic "github.com/go-gost/x/limiter/traffic"
	traffic_plugin "github.com/go-gost/x/limiter/traffic/plugin"
)

func ParseTrafficLimiter(cfg *config.LimiterConfig) (lim traffic.TrafficLimiter) {
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
			return traffic_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		default:
			return traffic_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			)
		}
	}

	var opts []xtraffic.Option

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xtraffic.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xtraffic.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xtraffic.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xtraffic.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	opts = append(opts,
		xtraffic.LimitsOption(cfg.Limits...),
		xtraffic.ReloadPeriodOption(cfg.Reload),
		xtraffic.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": cfg.Name,
		})),
	)

	return xtraffic.NewTrafficLimiter(opts...)
}

func ParseConnLimiter(cfg *config.LimiterConfig) (lim conn.ConnLimiter) {
	if cfg == nil {
		return nil
	}

	var opts []xconn.Option

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xconn.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xconn.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xconn.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xconn.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	opts = append(opts,
		xconn.LimitsOption(cfg.Limits...),
		xconn.ReloadPeriodOption(cfg.Reload),
		xconn.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": cfg.Name,
		})),
	)

	return xconn.NewConnLimiter(opts...)
}

func ParseRateLimiter(cfg *config.LimiterConfig) (lim rate.RateLimiter) {
	if cfg == nil {
		return nil
	}

	var opts []xrate.Option

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xrate.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xrate.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xrate.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xrate.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	opts = append(opts,
		xrate.LimitsOption(cfg.Limits...),
		xrate.ReloadPeriodOption(cfg.Reload),
		xrate.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": cfg.Name,
		})),
	)

	return xrate.NewRateLimiter(opts...)
}
