package rewriter

import (
	"crypto/tls"
	"strings"

	"github.com/go-gost/core/rewriter"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/plugin"
	rewriter_plugin "github.com/go-gost/x/rewriter/plugin"
)

// ParseRewriter converts a RewriterConfig into a rewriter.Rewriter.
// It currently supports plugin backends only (HTTP or gRPC).
// Returns nil when cfg is nil or no backend is configured.
func ParseRewriter(cfg *config.RewriterConfig) rewriter.Rewriter {
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
			return rewriter_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		default:
			return rewriter_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		}
	}

	return nil
}
