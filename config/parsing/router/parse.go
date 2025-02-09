package router

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/router"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/plugin"
	xrouter "github.com/go-gost/x/router"
	router_plugin "github.com/go-gost/x/router/plugin"
)

func ParseRouter(cfg *config.RouterConfig) router.Router {
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
			return router_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		default:
			return router_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			)
		}
	}

	var routes []*router.Route
	for _, route := range cfg.Routes {
		if route == nil {
			continue
		}
		_, ipNet, _ := net.ParseCIDR(route.Net)
		dst := route.Dst
		if dst != "" {
			_, ipNet, _ = net.ParseCIDR(dst)
		} else {
			if ipNet != nil {
				dst = ipNet.String()
			}
		}

		if dst == "" || route.Gateway == "" {
			continue
		}

		routes = append(routes, &router.Route{
			Net:     ipNet,
			Dst:     dst,
			Gateway: route.Gateway,
		})
	}
	opts := []xrouter.Option{
		xrouter.RoutesOption(routes),
		xrouter.ReloadPeriodOption(cfg.Reload),
		xrouter.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":   "router",
			"router": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xrouter.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // rediss list
			opts = append(opts, xrouter.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		case "set": // redis set
			opts = append(opts, xrouter.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis hash
			opts = append(opts, xrouter.RedisLoaderOption(loader.RedisHashLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xrouter.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xrouter.NewRouter(opts...)
}
