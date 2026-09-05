// Package p2p converts a [config.P2PConfig] into a p2p.TunnelProvider.
package p2p

import (
	"crypto/tls"
	"strings"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/plugin"
	xp2p "github.com/go-gost/x/p2p"
	p2p_plugin "github.com/go-gost/x/p2p/plugin"
)

// ParseP2P converts a P2PConfig into a p2p.TunnelProvider backed by an
// external gRPC plugin. Returns nil when cfg is nil or no plugin is
// configured. The HTTP plugin variant is not implemented; configuring it
// logs a deprecation notice and falls back to gRPC.
func ParseP2P(cfg *config.P2PConfig) (p xp2p.TunnelProvider) {
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
		logger.Default().Warn("p2p: http plugin type is deprecated/unimplemented, falling back to grpc")
		fallthrough
	default:
		return p2p_plugin.NewGRPCPlugin(
			cfg.Name, cfg.Plugin.Addr,
			plugin.TokenOption(cfg.Plugin.Token),
			plugin.TLSConfigOption(tlsCfg),
		)
	}
}