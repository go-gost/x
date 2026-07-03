package node

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	xauth "github.com/go-gost/x/auth"
	xbypass "github.com/go-gost/x/bypass"
	xchain "github.com/go-gost/x/chain"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	auth_parser "github.com/go-gost/x/config/parsing/auth"
	bypass_parser "github.com/go-gost/x/config/parsing/bypass"
	tls_util "github.com/go-gost/x/internal/util/tls"
	mdx "github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/routing"
)

// MaxMatcherBodySize bounds the request body prefix (in bytes) exposed to
// body matchers via routing.Request.Body. It protects against unbounded
// buffering when a node opts in to body matching.
const MaxMatcherBodySize = 1 << 20 // 1MB

// ParseNode converts a NodeConfig into a *chain.Node. It resolves the
// connector and dialer from their registries, applies TLS settings, extracts
// metadata-driven options (so_mark, interface, netns, proxy protocol), sets up
// bypass rules, node filters, HTTP settings, and TLS node settings. The hop
// parameter is used only for logging context.

func parseBodyRewrites(vs []config.HTTPBodyRewriteConfig, log logger.Logger) []chain.HTTPBodyRewriteSettings {
	var out []chain.HTTPBodyRewriteSettings
	for _, v := range vs {
		pattern, _ := regexp.Compile(v.Match)
		rw := chain.HTTPBodyRewriteSettings{
			Type:         v.Type,
			Pattern:      pattern,
			Replacement:  []byte(v.Replacement),
			MaxChunkSize: v.MaxChunkSize,
		}
		if v.Rewriter != "" {
			if !registry.RewriterRegistry().IsRegistered(v.Rewriter) {
				log.Warnf("rewriter %q not found in registry for rewrite rule", v.Rewriter)
			}
			rw.Rewriter = registry.RewriterRegistry().Get(v.Rewriter)
		}
		if pattern != nil || rw.Rewriter != nil {
			out = append(out, rw)
		}
	}
	return out
}

func ParseNode(hop string, cfg *config.NodeConfig, log logger.Logger) (*chain.Node, error) {
	if cfg == nil {
		return nil, nil
	}

	connCfg := cfg.Connector
	if connCfg == nil {
		connCfg = &config.ConnectorConfig{}
	}
	if connCfg.Type == "" {
		connCfg.Type = "http"
	}

	dialCfg := cfg.Dialer
	if dialCfg == nil {
		dialCfg = &config.DialerConfig{}
	}
	if dialCfg.Type == "" {
		dialCfg.Type = "tcp"
	}

	nodeLogger := log.WithFields(map[string]any{
		"hop":       hop,
		"kind":      "node",
		"node":      cfg.Name,
		"connector": connCfg.Type,
		"dialer":    dialCfg.Type,
	})

	serverName, _, _ := net.SplitHostPort(cfg.Addr)

	tlsCfg := connCfg.TLS
	if tlsCfg == nil {
		tlsCfg = &config.TLSConfig{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = serverName
	}
	tlsConfig, err := tls_util.LoadClientConfig(tlsCfg)
	if err != nil {
		nodeLogger.Error(err)
		return nil, err
	}

	connectorLogger := nodeLogger.WithFields(map[string]any{
		"kind": "connector",
	})
	var cr connector.Connector
	if rf := registry.ConnectorRegistry().Get(connCfg.Type); rf != nil {
		cr = rf(
			connector.AuthOption(auth_parser.Info(connCfg.Auth)),
			connector.TLSConfigOption(tlsConfig),
			connector.LoggerOption(connectorLogger),
		)
	} else {
		return nil, fmt.Errorf("unregistered connector: %s", connCfg.Type)
	}

	if err := cr.Init(mdx.NewMetadata(connCfg.Metadata)); err != nil {
		connectorLogger.Error("init: ", err)
		return nil, err
	}

	tlsCfg = dialCfg.TLS
	if tlsCfg == nil {
		tlsCfg = &config.TLSConfig{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = serverName
	}
	tlsConfig, err = tls_util.LoadClientConfig(tlsCfg)
	if err != nil {
		nodeLogger.Error(err)
		return nil, err
	}

	md := mdx.NewMetadata(cfg.Metadata)

	dialerLogger := nodeLogger.WithFields(map[string]any{
		"kind": "dialer",
	})

	var d dialer.Dialer
	if rf := registry.DialerRegistry().Get(dialCfg.Type); rf != nil {
		d = rf(
			dialer.AuthOption(auth_parser.Info(dialCfg.Auth)),
			dialer.TLSConfigOption(tlsConfig),
			dialer.LoggerOption(dialerLogger),
			dialer.ProxyProtocolOption(mdutil.GetInt(md, parsing.MDKeyProxyProtocol)),
		)
	} else {
		return nil, fmt.Errorf("unregistered dialer: %s", dialCfg.Type)
	}

	if err := d.Init(mdx.NewMetadata(dialCfg.Metadata)); err != nil {
		dialerLogger.Error("init: ", err)
		return nil, err
	}

	var sockOpts *chain.SockOpts
	if v := mdutil.GetInt(md, parsing.MDKeySoMark); v != 0 {
		sockOpts = &chain.SockOpts{
			Mark: v,
		}
	}

	tr := xchain.NewTransport(d, cr,
		chain.AddrTransportOption(cfg.Addr),
		chain.InterfaceTransportOption(mdutil.GetString(md, parsing.MDKeyInterface)),
		chain.NetnsTransportOption(mdutil.GetString(md, parsing.MDKeyNetns)),
		chain.SockOptsTransportOption(sockOpts),
	)

	opts := []chain.NodeOption{
		chain.TransportNodeOption(tr),
		chain.BypassNodeOption(xbypass.BypassGroup(bypass_parser.List(cfg.Bypass, cfg.Bypasses...)...)),
		chain.ResolverNodeOption(registry.ResolverRegistry().Get(cfg.Resolver)),
		chain.HostMapperNodeOption(registry.HostsRegistry().Get(cfg.Hosts)),
		chain.MetadataNodeOption(md),
		chain.NetworkNodeOption(cfg.Network),
	}

	if filter := cfg.Filter; filter != nil {
		// convert *.example.com to .example.com
		// convert *example.com to example.com
		host := filter.Host
		if strings.HasPrefix(host, "*") {
			host = host[1:]
			if !strings.HasPrefix(host, ".") {
				host = "." + host
			}
		}

		settings := &chain.NodeFilterSettings{
			Protocol: filter.Protocol,
			Host:     host,
			Path:     filter.Path,
		}
		opts = append(opts, chain.NodeFilterOption(settings))
	}

	if cfg.Matcher != nil {
		priority := cfg.Matcher.Priority

		if rule := strings.TrimSpace(cfg.Matcher.Rule); rule != "" {
			if matcher, err := routing.NewMatcher(rule); err == nil {
				log.Debugf("new matcher for node %s with rule %s", cfg.Name, cfg.Matcher.Rule)
				// Priority 0 means "use default": automatically set to the
				// rule length so longer (more specific) rules outrank shorter
				// ones. Use a negative priority to opt out of this behavior
				// and always go through the selector.
				if priority == 0 {
					priority = len(cfg.Matcher.Rule)
				}
				opts = append(opts, chain.MatcherNodeOption(matcher))
			} else {
				log.Error(err)
				priority = -1
			}
		}

		if bodySize := cfg.Matcher.BodySize; bodySize > 0 {
			if bodySize > MaxMatcherBodySize {
				bodySize = MaxMatcherBodySize
			}
			opts = append(opts, chain.MatcherBodySizeNodeOption(bodySize))
		}

		opts = append(opts, chain.PriorityNodeOption(priority))
	}

	if cfg.HTTP != nil {
		settings := &chain.HTTPNodeSettings{
			Host:           cfg.HTTP.Host,
			RequestHeader:  cfg.HTTP.RequestHeader,
			ResponseHeader: cfg.HTTP.ResponseHeader,
		}
		if settings.RequestHeader == nil {
			settings.RequestHeader = cfg.HTTP.Header
		}

		if auth := cfg.HTTP.Auth; auth != nil && auth.Username != "" {
			settings.Auther = xauth.NewAuthenticator(
				xauth.AuthsOption(map[string]string{auth.Username: auth.Password}),
				xauth.LoggerOption(log.WithFields(map[string]any{
					"kind": "node",
					"node": cfg.Name,
					"addr": cfg.Addr,
				})),
			)
		}

		rewriteURL := cfg.HTTP.RewriteURL
		if rewriteURL == nil {
			rewriteURL = cfg.HTTP.Rewrite
		}
		for _, v := range rewriteURL {
			if pattern, _ := regexp.Compile(v.Match); pattern != nil {
				settings.RewriteURL = append(settings.RewriteURL, chain.HTTPURLRewriteSetting{
					Pattern:     pattern,
					Replacement: v.Replacement,
				})
			}
		}
		settings.RewriteResponseBody = append(settings.RewriteResponseBody, parseBodyRewrites(cfg.HTTP.RewriteBody, log)...)
		settings.RewriteResponseBody = append(settings.RewriteResponseBody, parseBodyRewrites(cfg.HTTP.RewriteResponseBody, log)...)
		settings.RewriteRequestBody = append(settings.RewriteRequestBody, parseBodyRewrites(cfg.HTTP.RewriteRequestBody, log)...)
		opts = append(opts, chain.HTTPNodeOption(settings))
	}

	if cfg.TLS != nil {
		tlsCfg := &chain.TLSNodeSettings{
			ServerName: cfg.TLS.ServerName,
			Secure:     cfg.TLS.Secure,
		}
		if o := cfg.TLS.Options; o != nil {
			tlsCfg.Options.MinVersion = o.MinVersion
			tlsCfg.Options.MaxVersion = o.MaxVersion
			tlsCfg.Options.CipherSuites = o.CipherSuites
			tlsCfg.Options.ALPN = o.ALPN
		}
		opts = append(opts, chain.TLSNodeOption(tlsCfg))
	}
	return chain.NewNode(cfg.Name, cfg.Addr, opts...), nil
}
