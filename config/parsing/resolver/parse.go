package resolver

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/plugin"
	"github.com/go-gost/x/registry"
	xresolver "github.com/go-gost/x/resolver"
	resolver_plugin "github.com/go-gost/x/resolver/plugin"
)

func ParseResolver(cfg *config.ResolverConfig) (resolver.Resolver, error) {
	if cfg == nil {
		return nil, nil
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
			return resolver_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			), nil
		default:
			return resolver_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			)
		}
	}

	var nameservers []xresolver.NameServer
	for _, server := range cfg.Nameservers {
		nameservers = append(nameservers, xresolver.NameServer{
			Addr:     server.Addr,
			Chain:    registry.ChainRegistry().Get(server.Chain),
			TTL:      server.TTL,
			Timeout:  server.Timeout,
			ClientIP: net.ParseIP(server.ClientIP),
			Prefer:   server.Prefer,
			Hostname: server.Hostname,
			Async:    server.Async,
			Only:     server.Only,
		})
	}

	return xresolver.NewResolver(
		nameservers,
		xresolver.LoggerOption(
			logger.Default().WithFields(map[string]any{
				"kind":     "resolver",
				"resolver": cfg.Name,
			}),
		),
	)
}
