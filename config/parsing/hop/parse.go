package hop

import (
	"crypto/tls"
	"strings"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	bypass_parser "github.com/go-gost/x/config/parsing/bypass"
	node_parser "github.com/go-gost/x/config/parsing/node"
	selector_parser "github.com/go-gost/x/config/parsing/selector"
	xhop "github.com/go-gost/x/hop"
	hop_plugin "github.com/go-gost/x/hop/plugin"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/plugin"
	"github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

func ParseHop(cfg *config.HopConfig, log logger.Logger) (hop.Hop, error) {
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
		case plugin.HTTP:
			return hop_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			), nil
		default:
			return hop_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			), nil
		}
	}

	ifce := cfg.Interface
	var netns string
	if cfg.Metadata != nil {
		md := metadata.NewMetadata(cfg.Metadata)
		if v := mdutil.GetString(md, parsing.MDKeyInterface); v != "" {
			ifce = v
		}
		netns = mdutil.GetString(md, "netns")
	}

	var nodes []*chain.Node
	for _, v := range cfg.Nodes {
		if v == nil {
			continue
		}

		if v.Resolver == "" {
			v.Resolver = cfg.Resolver
		}
		if v.Hosts == "" {
			v.Hosts = cfg.Hosts
		}
		if v.Interface == "" {
			v.Interface = ifce
		}
		if v.Netns == "" {
			v.Netns = netns
		}

		if v.SockOpts == nil {
			v.SockOpts = cfg.SockOpts
		}

		if v.Connector == nil {
			v.Connector = &config.ConnectorConfig{}
		}
		if strings.TrimSpace(v.Connector.Type) == "" {
			v.Connector.Type = "http"
		}

		if v.Dialer == nil {
			v.Dialer = &config.DialerConfig{}
		}
		if strings.TrimSpace(v.Dialer.Type) == "" {
			v.Dialer.Type = "tcp"
		}

		node, err := node_parser.ParseNode(cfg.Name, v, log)
		if err != nil {
			return nil, err
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}

	sel := selector_parser.ParseNodeSelector(cfg.Selector)
	if sel == nil {
		sel = selector_parser.DefaultNodeSelector()
	}

	opts := []xhop.Option{
		xhop.NameOption(cfg.Name),
		xhop.NodeOption(nodes...),
		xhop.SelectorOption(sel),
		xhop.BypassOption(xbypass.BypassGroup(bypass_parser.List(cfg.Bypass, cfg.Bypasses...)...)),
		xhop.ReloadPeriodOption(cfg.Reload),
		xhop.LoggerOption(log.WithFields(map[string]any{
			"kind": "hop",
			"hop":  cfg.Name,
		})),
	}

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xhop.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		opts = append(opts, xhop.RedisLoaderOption(loader.RedisStringLoader(
			cfg.Redis.Addr,
			loader.DBRedisLoaderOption(cfg.Redis.DB),
			loader.UsernameRedisLoaderOption(cfg.Redis.Username),
			loader.PasswordRedisLoaderOption(cfg.Redis.Password),
			loader.KeyRedisLoaderOption(cfg.Redis.Key),
		)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xhop.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xhop.NewHop(opts...), nil
}
