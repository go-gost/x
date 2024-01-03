package sd

import (
	"crypto/tls"
	"strings"

	"github.com/go-gost/core/sd"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/plugin"
	sd_plugin "github.com/go-gost/x/sd/plugin"
)

func ParseSD(cfg *config.SDConfig) sd.SD {
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
		return sd_plugin.NewHTTPPlugin(
			cfg.Name, cfg.Plugin.Addr,
			plugin.TLSConfigOption(tlsCfg),
			plugin.TimeoutOption(cfg.Plugin.Timeout),
		)
	default:
		return sd_plugin.NewGRPCPlugin(
			cfg.Name, cfg.Plugin.Addr,
			plugin.TokenOption(cfg.Plugin.Token),
			plugin.TLSConfigOption(tlsCfg),
		)
	}
}
