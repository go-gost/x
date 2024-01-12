package service

import (
	"fmt"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/core/service"
	xchain "github.com/go-gost/x/chain"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	admission_parser "github.com/go-gost/x/config/parsing/admission"
	auth_parser "github.com/go-gost/x/config/parsing/auth"
	bypass_parser "github.com/go-gost/x/config/parsing/bypass"
	hop_parser "github.com/go-gost/x/config/parsing/hop"
	logger_parser "github.com/go-gost/x/config/parsing/logger"
	selector_parser "github.com/go-gost/x/config/parsing/selector"
	xnet "github.com/go-gost/x/internal/net"
	tls_util "github.com/go-gost/x/internal/util/tls"
	"github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
	xservice "github.com/go-gost/x/service"
	"github.com/go-gost/x/stats"
)

func ParseService(cfg *config.ServiceConfig) (service.Service, error) {
	if cfg.Listener == nil {
		cfg.Listener = &config.ListenerConfig{
			Type: "tcp",
		}
	}
	if cfg.Handler == nil {
		cfg.Handler = &config.HandlerConfig{
			Type: "auto",
		}
	}

	log := logger.Default()
	if loggers := logger_parser.List(cfg.Logger, cfg.Loggers...); len(loggers) > 0 {
		log = logger.LoggerGroup(loggers...)
	}

	serviceLogger := log.WithFields(map[string]any{
		"kind":     "service",
		"service":  cfg.Name,
		"listener": cfg.Listener.Type,
		"handler":  cfg.Handler.Type,
	})

	listenerLogger := serviceLogger.WithFields(map[string]any{
		"kind": "listener",
	})

	tlsCfg := cfg.Listener.TLS
	if tlsCfg == nil {
		tlsCfg = &config.TLSConfig{}
	}
	tlsConfig, err := tls_util.LoadServerConfig(tlsCfg)
	if err != nil {
		listenerLogger.Error(err)
		return nil, err
	}
	if tlsConfig == nil {
		tlsConfig = parsing.DefaultTLSConfig().Clone()
	}

	authers := auth_parser.List(cfg.Listener.Auther, cfg.Listener.Authers...)
	if len(authers) == 0 {
		if auther := auth_parser.ParseAutherFromAuth(cfg.Listener.Auth); auther != nil {
			authers = append(authers, auther)
		}
	}
	var auther auth.Authenticator
	if len(authers) > 0 {
		auther = auth.AuthenticatorGroup(authers...)
	}

	admissions := admission_parser.List(cfg.Admission, cfg.Admissions...)

	var sockOpts *chain.SockOpts
	if cfg.SockOpts != nil {
		sockOpts = &chain.SockOpts{
			Mark: cfg.SockOpts.Mark,
		}
	}

	var ppv int
	ifce := cfg.Interface
	var preUp, preDown, postUp, postDown []string
	var ignoreChain bool
	var pStats *stats.Stats
	if cfg.Metadata != nil {
		md := metadata.NewMetadata(cfg.Metadata)
		ppv = mdutil.GetInt(md, parsing.MDKeyProxyProtocol)
		if v := mdutil.GetString(md, parsing.MDKeyInterface); v != "" {
			ifce = v
		}
		if v := mdutil.GetInt(md, parsing.MDKeySoMark); v > 0 {
			sockOpts = &chain.SockOpts{
				Mark: v,
			}
		}
		preUp = mdutil.GetStrings(md, parsing.MDKeyPreUp)
		preDown = mdutil.GetStrings(md, parsing.MDKeyPreDown)
		postUp = mdutil.GetStrings(md, parsing.MDKeyPostUp)
		postDown = mdutil.GetStrings(md, parsing.MDKeyPostDown)
		ignoreChain = mdutil.GetBool(md, parsing.MDKeyIgnoreChain)

		if mdutil.GetBool(md, parsing.MDKeyEnableStats) {
			pStats = &stats.Stats{}
		}
	}

	listenOpts := []listener.Option{
		listener.AddrOption(cfg.Addr),
		listener.AutherOption(auther),
		listener.AuthOption(auth_parser.Info(cfg.Listener.Auth)),
		listener.TLSConfigOption(tlsConfig),
		listener.AdmissionOption(admission.AdmissionGroup(admissions...)),
		listener.TrafficLimiterOption(registry.TrafficLimiterRegistry().Get(cfg.Limiter)),
		listener.ConnLimiterOption(registry.ConnLimiterRegistry().Get(cfg.CLimiter)),
		listener.LoggerOption(listenerLogger),
		listener.ServiceOption(cfg.Name),
		listener.ProxyProtocolOption(ppv),
		listener.StatsOption(pStats),
	}
	if !ignoreChain {
		listenOpts = append(listenOpts,
			listener.ChainOption(chainGroup(cfg.Listener.Chain, cfg.Listener.ChainGroup)),
		)
	}

	var ln listener.Listener
	if rf := registry.ListenerRegistry().Get(cfg.Listener.Type); rf != nil {
		ln = rf(listenOpts...)
	} else {
		return nil, fmt.Errorf("unregistered listener: %s", cfg.Listener.Type)
	}

	if cfg.Listener.Metadata == nil {
		cfg.Listener.Metadata = make(map[string]any)
	}
	listenerLogger.Debugf("metadata: %v", cfg.Listener.Metadata)
	if err := ln.Init(metadata.NewMetadata(cfg.Listener.Metadata)); err != nil {
		listenerLogger.Error("init: ", err)
		return nil, err
	}

	handlerLogger := serviceLogger.WithFields(map[string]any{
		"kind": "handler",
	})

	tlsCfg = cfg.Handler.TLS
	if tlsCfg == nil {
		tlsCfg = &config.TLSConfig{}
	}
	tlsConfig, err = tls_util.LoadServerConfig(tlsCfg)
	if err != nil {
		handlerLogger.Error(err)
		return nil, err
	}
	if tlsConfig == nil {
		tlsConfig = parsing.DefaultTLSConfig().Clone()
	}

	authers = auth_parser.List(cfg.Handler.Auther, cfg.Handler.Authers...)
	if len(authers) == 0 {
		if auther := auth_parser.ParseAutherFromAuth(cfg.Handler.Auth); auther != nil {
			authers = append(authers, auther)
		}
	}

	auther = nil
	if len(authers) > 0 {
		auther = auth.AuthenticatorGroup(authers...)
	}

	var recorders []recorder.RecorderObject
	for _, r := range cfg.Recorders {
		md := metadata.NewMetadata(r.Metadata)
		recorders = append(recorders, recorder.RecorderObject{
			Recorder: registry.RecorderRegistry().Get(r.Name),
			Record:   r.Record,
			Options: &recorder.Options{
				Direction:       mdutil.GetBool(md, parsing.MDKeyRecorderDirection),
				TimestampFormat: mdutil.GetString(md, parsing.MDKeyRecorderTimestampFormat),
				Hexdump:         mdutil.GetBool(md, parsing.MDKeyRecorderHexdump),
			},
		})
	}

	routerOpts := []chain.RouterOption{
		chain.RetriesRouterOption(cfg.Handler.Retries),
		// chain.TimeoutRouterOption(10*time.Second),
		chain.InterfaceRouterOption(ifce),
		chain.SockOptsRouterOption(sockOpts),
		chain.ResolverRouterOption(registry.ResolverRegistry().Get(cfg.Resolver)),
		chain.HostMapperRouterOption(registry.HostsRegistry().Get(cfg.Hosts)),
		chain.RecordersRouterOption(recorders...),
		chain.LoggerRouterOption(handlerLogger),
	}
	if !ignoreChain {
		routerOpts = append(routerOpts,
			chain.ChainRouterOption(chainGroup(cfg.Handler.Chain, cfg.Handler.ChainGroup)),
		)
	}
	router := chain.NewRouter(routerOpts...)

	var h handler.Handler
	if rf := registry.HandlerRegistry().Get(cfg.Handler.Type); rf != nil {
		h = rf(
			handler.RouterOption(router),
			handler.AutherOption(auther),
			handler.AuthOption(auth_parser.Info(cfg.Handler.Auth)),
			handler.BypassOption(bypass.BypassGroup(bypass_parser.List(cfg.Bypass, cfg.Bypasses...)...)),
			handler.TLSConfigOption(tlsConfig),
			handler.RateLimiterOption(registry.RateLimiterRegistry().Get(cfg.RLimiter)),
			handler.TrafficLimiterOption(registry.TrafficLimiterRegistry().Get(cfg.Handler.Limiter)),
			handler.ObserverOption(registry.ObserverRegistry().Get(cfg.Handler.Observer)),
			handler.LoggerOption(handlerLogger),
			handler.ServiceOption(cfg.Name),
		)
	} else {
		return nil, fmt.Errorf("unregistered handler: %s", cfg.Handler.Type)
	}

	if forwarder, ok := h.(handler.Forwarder); ok {
		hop, err := parseForwarder(cfg.Forwarder, log)
		if err != nil {
			return nil, err
		}
		forwarder.Forward(hop)
	}

	if cfg.Handler.Metadata == nil {
		cfg.Handler.Metadata = make(map[string]any)
	}
	handlerLogger.Debugf("metadata: %v", cfg.Handler.Metadata)
	if err := h.Init(metadata.NewMetadata(cfg.Handler.Metadata)); err != nil {
		handlerLogger.Error("init: ", err)
		return nil, err
	}

	s := xservice.NewService(cfg.Name, ln, h,
		xservice.AdmissionOption(admission.AdmissionGroup(admissions...)),
		xservice.PreUpOption(preUp),
		xservice.PreDownOption(preDown),
		xservice.PostUpOption(postUp),
		xservice.PostDownOption(postDown),
		xservice.RecordersOption(recorders...),
		xservice.StatsOption(pStats),
		xservice.ObserverOption(registry.ObserverRegistry().Get(cfg.Observer)),
		xservice.LoggerOption(serviceLogger),
	)

	serviceLogger.Infof("listening on %s/%s", s.Addr().String(), s.Addr().Network())
	return s, nil
}

func parseForwarder(cfg *config.ForwarderConfig, log logger.Logger) (hop.Hop, error) {
	if cfg == nil {
		return nil, nil
	}

	hc := config.HopConfig{
		Name:     cfg.Name,
		Selector: cfg.Selector,
	}
	for _, node := range cfg.Nodes {
		if node != nil {
			addrs := xnet.AddrPortRange(node.Addr).Addrs()
			if len(addrs) == 0 {
				addrs = append(addrs, node.Addr)
			}
			for i, addr := range addrs {
				name := node.Name
				if i > 0 {
					name = fmt.Sprintf("%s-%d", node.Name, i)
				}
				hc.Nodes = append(hc.Nodes, &config.NodeConfig{
					Name:     name,
					Addr:     addr,
					Host:     node.Host,
					Network:  node.Network,
					Protocol: node.Protocol,
					Path:     node.Path,
					Bypass:   node.Bypass,
					Bypasses: node.Bypasses,
					HTTP:     node.HTTP,
					TLS:      node.TLS,
					Auth:     node.Auth,
					Metadata: node.Metadata,
				})
			}
		}
	}
	if len(hc.Nodes) > 0 {
		return hop_parser.ParseHop(&hc, log)
	}
	return registry.HopRegistry().Get(hc.Name), nil
}

func chainGroup(name string, group *config.ChainGroupConfig) chain.Chainer {
	var chains []chain.Chainer
	var sel selector.Selector[chain.Chainer]

	if c := registry.ChainRegistry().Get(name); c != nil {
		chains = append(chains, c)
	}
	if group != nil {
		for _, s := range group.Chains {
			if c := registry.ChainRegistry().Get(s); c != nil {
				chains = append(chains, c)
			}
		}
		sel = selector_parser.ParseChainSelector(group.Selector)
	}
	if len(chains) == 0 {
		return nil
	}

	if sel == nil {
		sel = selector_parser.DefaultChainSelector()
	}

	return xchain.NewChainGroup(chains...).
		WithSelector(sel)
}
