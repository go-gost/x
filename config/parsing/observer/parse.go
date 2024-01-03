package observer

import (
	"crypto/tls"
	"strings"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/plugin"
	observer_plugin "github.com/go-gost/x/observer/plugin"
)

func ParseObserver(cfg *config.ObserverConfig) observer.Observer {
	if cfg == nil || cfg.Plugin == nil {
		return nil
	}

	var tlsCfg *tls.Config
	if cfg.Plugin.TLS != nil {
		tlsCfg = &tls.Config{
			ServerName:         cfg.Plugin.TLS.ServerName,
			InsecureSkipVerify: !cfg.Plugin.TLS.Secure,
		}
	}
	switch strings.ToLower(cfg.Plugin.Type) {
	case "http":
		return observer_plugin.NewHTTPPlugin(
			cfg.Name, cfg.Plugin.Addr,
			plugin.TLSConfigOption(tlsCfg),
			plugin.TimeoutOption(cfg.Plugin.Timeout),
		)
	default:
		return observer_plugin.NewGRPCPlugin(
			cfg.Name, cfg.Plugin.Addr,
			plugin.TokenOption(cfg.Plugin.Token),
			plugin.TLSConfigOption(tlsCfg),
		)
	}
}
