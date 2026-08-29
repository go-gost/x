package node

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

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

// DefaultMatcherBodySize is the default request body prefix (in bytes) exposed
// to body matchers when a node has BodyRegexp/BodyJSON matchers but no
// explicit bodySize.
const DefaultMatcherBodySize = 1 << 20 // 1MB

// MaxMatcherBodySize is the hard cap for matcher body prefix. Values above
// this are silently clamped. Protects against unbounded in-memory buffering
// when a node opts in to body matching.
const MaxMatcherBodySize = 10 << 20 // 10MB

// filterToMatcherRule converts a deprecated NodeFilterConfig (host/protocol/
// path) into an equivalent matcher DSL rule. Empty fields are omitted; an
// empty result means the node is unconditional. Path maps to PathPrefix
// (the legacy filter is a prefix match, not exact).
func filterToMatcherRule(filter *config.NodeFilterConfig) string {
	if filter == nil {
		return ""
	}
	var parts []string
	// Normalize the legacy host forms first: `*.example.com` and
	// `.example.com` both meant "apex AND subdomains" in the legacy filter.
	// Strip the wildcard so the leading-dot branch below handles both.
	host := filter.Host
	if strings.HasPrefix(host, "*") {
		host = host[1:]
		if !strings.HasPrefix(host, ".") {
			host = "." + host
		}
	}
	if host != "" {
		// A leading-dot host matches the apex AND its subdomains in the
		// legacy filter (HasSuffix on the dot-stripped form), but matcher
		// Host(.x) only matches subdomains. Emit both to preserve apex
		// coverage. Parenthesize the OR when other conjuncts follow, since
		// && binds tighter than || in the matcher DSL.
		if strings.HasPrefix(host, ".") {
			h := "Host(`" + host[1:] + "`) || Host(`" + host + "`)"
			if filter.Protocol != "" || filter.Path != "" {
				h = "(" + h + ")"
			}
			parts = append(parts, h)
		} else {
			parts = append(parts, "Host(`"+host+"`)")
		}
	}
	if prot := filter.Protocol; prot != "" {
		parts = append(parts, "Proto(`"+prot+"`)")
	}
	if path := filter.Path; path != "" {
		parts = append(parts, "PathPrefix(`"+path+"`)")
	}
	return strings.Join(parts, " && ")
}

// ParseNode converts a NodeConfig into a *chain.Node. It resolves the
// connector and dialer from their registries, applies TLS settings, extracts
// metadata-driven options (so_mark, interface, netns, proxy protocol), sets up
// bypass rules, node filters, HTTP settings, and TLS node settings. The hop
// parameter is used only for logging context.

func parseBodyRewrites(vs []config.HTTPBodyRewriteConfig, log logger.Logger) []chain.HTTPBodyRewriteSettings {
	var out []chain.HTTPBodyRewriteSettings
	for _, v := range vs {
		var pattern *regexp.Regexp
		var rewriteType string

		js, ok := strings.CutPrefix(v.Match, "json:")
		del := false
		if !ok {
			// json-:<path> deletes the matched JSON field instead of replacing it.
			if js, ok = strings.CutPrefix(v.Match, "json-:"); ok {
				del = true
			}
		}
		if ok {
			// json:<path>[=<value-regex>] or json-:<path>[=<value-regex>]
			path, valRegex, _ := strings.Cut(js, "=")
			if valRegex == "" {
				valRegex = ".*"
			}
			var err error
			pattern, err = regexp.Compile(valRegex)
			if err != nil {
				log.Warnf("invalid JSON value regex %q for path %q: %v", valRegex, path, err)
				continue
			}
			if del {
				rewriteType = "json-:" + path
			} else {
				rewriteType = "json:" + path
			}
		} else {
			if v.Match != "" {
				pattern, _ = regexp.Compile(v.Match)
			}
			rewriteType = v.Type
		}

		rw := chain.HTTPBodyRewriteSettings{
			Type:         rewriteType,
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

func parseHeaderRewrites(vs []config.HTTPHeaderRewriteConfig, log logger.Logger) []chain.HTTPHeaderRewriteSettings {
	var out []chain.HTTPHeaderRewriteSettings
	for _, v := range vs {
		var name, pattern *regexp.Regexp
		if v.Name != "" {
			name, _ = regexp.Compile(v.Name)
		}
		if v.Match != "" {
			pattern, _ = regexp.Compile(v.Match)
		}

		rw := chain.HTTPHeaderRewriteSettings{
			Name:        name,
			Pattern:     pattern,
			Replacement: []byte(v.Replacement),
		}
		if v.Rewriter != "" {
			if !registry.RewriterRegistry().IsRegistered(v.Rewriter) {
				log.Warnf("rewriter %q not found in registry for rewrite rule", v.Rewriter)
			}
			rw.Rewriter = registry.RewriterRegistry().Get(v.Rewriter)
		}
		// Gate on the config string, not the compiled regexp: regexp.Compile("")
		// returns a non-nil match-all regexp, so an empty Name with no rewriter
		// would otherwise become a silent no-op rule.
		if v.Name != "" || rw.Rewriter != nil {
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

	var (
		rule     string
		priority int
		bodySize int
	)

	// Deprecated filter: normalize into an equivalent matcher DSL rule so the
	// runtime keeps a single filtering logic. Explicit -1 priority opts out of
	// auto-priority and the priority short-circuit, preserving the legacy
	// filter behavior (always through the selector).
	if filter := cfg.Filter; filter != nil {
		rule = filterToMatcherRule(filter)
		priority = -1
		bodySize = DefaultMatcherBodySize
	}

	if cfg.Matcher != nil {
		priority = cfg.Matcher.Priority
		rule = cfg.Matcher.Rule
		bodySize = cfg.Matcher.BodySize
	}

	if rule = strings.TrimSpace(rule); rule != "" {
		if matcher, err := routing.NewMatcher(rule); err == nil {
			log.Debugf("new matcher for node %s with rule %s", cfg.Name, rule)
			// Priority 0 means "use default": automatically set to the
			// rule length so longer (more specific) rules outrank shorter
			// ones. Use a negative priority to opt out of this behavior
			// and always go through the selector.
			if priority == 0 {
				priority = len(rule)
			}
			opts = append(opts, chain.MatcherNodeOption(matcher))
		} else {
			log.Error(err)
			priority = -1
		}
	}

	if bodySize <= 0 {
		bodySize = DefaultMatcherBodySize
	} else if bodySize > MaxMatcherBodySize {
		bodySize = MaxMatcherBodySize
	}
	opts = append(opts, chain.MatcherBodySizeNodeOption(bodySize))
	opts = append(opts, chain.PriorityNodeOption(priority))

	if cfg.HTTP != nil {
		settings := &chain.HTTPNodeSettings{
			Host:           cfg.HTTP.Host,
			RequestHeader:  cfg.HTTP.RequestHeader,
			ResponseHeader: cfg.HTTP.ResponseHeader,
		}
		if settings.RequestHeader == nil {
			settings.RequestHeader = cfg.HTTP.Header
		}

		if v := cfg.HTTP.HostPattern; v != "" {
			settings.HostPattern, _ = regexp.Compile(v)
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
		settings.RewriteRequestHeader = parseHeaderRewrites(cfg.HTTP.RewriteRequestHeader, log)
		settings.RewriteResponseHeader = parseHeaderRewrites(cfg.HTTP.RewriteResponseHeader, log)

		if v := strings.TrimSpace(cfg.HTTP.FailCodes); v != "" {
			settings.FailCodes = parseFailCodes(v, nodeLogger)
		}

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

	node := chain.NewNode(cfg.Name, cfg.Addr, opts...)
	if cfg.Probe != nil {
		if pc := ParseProbeConfig(cfg.Probe); pc != nil {
			xchain.StartNodeProbe(node, pc, nodeLogger)
		}
	}
	return node, nil
}

// ParseProbeConfig converts a config.ProbeConfig into a chain.ProbeConfig.
// Returns nil when the config is invalid (e.g. empty addr).
func ParseProbeConfig(cfg *config.ProbeConfig) *chain.ProbeConfig {
	if cfg == nil || (cfg.Addr == "" && cfg.Type != "cmd") {
		return nil
	}
	if cfg.Type == "cmd" && cfg.Command == "" {
		return nil
	}
	pt := chain.ProbeTypeTCP
	switch cfg.Type {
	case "http":
		pt = chain.ProbeTypeHTTP
	case "cmd":
		pt = chain.ProbeTypeCmd
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &chain.ProbeConfig{
		Type:           pt,
		Addr:           cfg.Addr,
		Interval:       interval,
		Timeout:        timeout,
		HTTPPath:       cfg.HTTPPath,
		HTTPHost:       cfg.HTTPHost,
		HTTPHeaders:    cfg.HTTPHeaders,
		ExpectedStatus: cfg.ExpectedStatus,
		Command:        cfg.Command,
	}
}

// parseFailCodes parses a comma-separated status code list, e.g. "429,5xx".
// Tokens ending in "xx" become hundred-level wildcards (5xx → 5, matching
// 500-599). Invalid tokens are logged and skipped.
func parseFailCodes(s string, log logger.Logger) chain.FailCodes {
	var codes chain.FailCodes
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if len(part) == 3 && strings.HasSuffix(part, "xx") {
			if prefix, err := strconv.Atoi(part[:1]); err == nil && prefix > 0 {
				codes = append(codes, prefix) // < 100 → wildcard
				continue
			}
		} else if code, err := strconv.Atoi(part); err == nil && code >= 100 {
			codes = append(codes, code)
			continue
		}
		log.Warnf("failCodes: invalid token %q", part)
	}
	return codes
}
