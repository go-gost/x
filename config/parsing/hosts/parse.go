package hosts

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xhosts "github.com/go-gost/x/hosts"
	hosts_plugin "github.com/go-gost/x/hosts/plugin"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/plugin"
)

func ParseHostMapper(cfg *config.HostsConfig) hosts.HostMapper {
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
			return hosts_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		default:
			return hosts_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			)
		}
	}

	var mappings []xhosts.Mapping
	for _, mapping := range cfg.Mappings {
		if mapping.IP == "" || mapping.Hostname == "" {
			continue
		}

		ip := net.ParseIP(mapping.IP)
		if ip == nil {
			continue
		}
		mappings = append(mappings, xhosts.Mapping{
			Hostname: mapping.Hostname,
			IP:       ip,
		})
	}
	opts := []xhosts.Option{
		xhosts.MappingsOption(mappings),
		xhosts.ReloadPeriodOption(cfg.Reload),
		xhosts.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":  "hosts",
			"hosts": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xhosts.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xhosts.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xhosts.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.UsernameRedisLoaderOption(cfg.Redis.Username),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xhosts.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xhosts.NewHostMapper(opts...)
}
