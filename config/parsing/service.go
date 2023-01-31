package parsing

import (
	"fmt"
	"strings"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/core/service"
	xchain "github.com/go-gost/x/chain"
	"github.com/go-gost/x/config"
	tls_util "github.com/go-gost/x/internal/util/tls"
	"github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
	xservice "github.com/go-gost/x/service"
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
	serviceLogger := logger.Default().WithFields(map[string]any{
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
	tlsConfig, err := tls_util.LoadServerConfig(
		tlsCfg.CertFile, tlsCfg.KeyFile, tlsCfg.CAFile)
	if err != nil {
		listenerLogger.Error(err)
		return nil, err
	}
	if tlsConfig == nil {
		tlsConfig = defaultTLSConfig.Clone()
	}

	authers := autherList(cfg.Listener.Auther, cfg.Listener.Authers...)
	if len(authers) == 0 {
		if auther := ParseAutherFromAuth(cfg.Listener.Auth); auther != nil {
			authers = append(authers, auther)
		}
	}
	var auther auth.Authenticator
	if len(authers) > 0 {
		auther = auth.AuthenticatorGroup(authers...)
	}

	admissions := admissionList(cfg.Admission, cfg.Admissions...)

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
	if cfg.Metadata != nil {
		md := metadata.NewMetadata(cfg.Metadata)
		ppv = mdutil.GetInt(md, mdKeyProxyProtocol)
		if v := mdutil.GetString(md, mdKeyInterface); v != "" {
			ifce = v
		}
		if v := mdutil.GetInt(md, mdKeySoMark); v > 0 {
			sockOpts = &chain.SockOpts{
				Mark: v,
			}
		}
		preUp = mdutil.GetStrings(md, mdKeyPreUp)
		preDown = mdutil.GetStrings(md, mdKeyPreDown)
		postUp = mdutil.GetStrings(md, mdKeyPostUp)
		postDown = mdutil.GetStrings(md, mdKeyPostDown)
		ignoreChain = mdutil.GetBool(md, mdKeyIgnoreChain)
	}

	listenOpts := []listener.Option{
		listener.AddrOption(cfg.Addr),
		listener.AutherOption(auther),
		listener.AuthOption(parseAuth(cfg.Listener.Auth)),
		listener.TLSConfigOption(tlsConfig),
		listener.AdmissionOption(admission.AdmissionGroup(admissions...)),
		listener.TrafficLimiterOption(registry.TrafficLimiterRegistry().Get(cfg.Limiter)),
		listener.ConnLimiterOption(registry.ConnLimiterRegistry().Get(cfg.CLimiter)),
		listener.LoggerOption(listenerLogger),
		listener.ServiceOption(cfg.Name),
		listener.ProxyProtocolOption(ppv),
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
	tlsConfig, err = tls_util.LoadServerConfig(
		tlsCfg.CertFile, tlsCfg.KeyFile, tlsCfg.CAFile)
	if err != nil {
		handlerLogger.Error(err)
		return nil, err
	}
	if tlsConfig == nil {
		tlsConfig = defaultTLSConfig.Clone()
	}

	authers = autherList(cfg.Handler.Auther, cfg.Handler.Authers...)
	if len(authers) == 0 {
		if auther := ParseAutherFromAuth(cfg.Handler.Auth); auther != nil {
			authers = append(authers, auther)
		}
	}

	auther = nil
	if len(authers) > 0 {
		auther = auth.AuthenticatorGroup(authers...)
	}

	var recorders []recorder.RecorderObject
	for _, r := range cfg.Recorders {
		recorders = append(recorders, recorder.RecorderObject{
			Recorder: registry.RecorderRegistry().Get(r.Name),
			Record:   r.Record,
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
			handler.AuthOption(parseAuth(cfg.Handler.Auth)),
			handler.BypassOption(bypass.BypassGroup(bypassList(cfg.Bypass, cfg.Bypasses...)...)),
			handler.TLSConfigOption(tlsConfig),
			handler.RateLimiterOption(registry.RateLimiterRegistry().Get(cfg.RLimiter)),
			handler.LoggerOption(handlerLogger),
			handler.ServiceOption(cfg.Name),
		)
	} else {
		return nil, fmt.Errorf("unregistered handler: %s", cfg.Handler.Type)
	}

	if forwarder, ok := h.(handler.Forwarder); ok {
		hop, err := parseForwarder(cfg.Forwarder)
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
		xservice.LoggerOption(serviceLogger),
	)

	serviceLogger.Infof("listening on %s/%s", s.Addr().String(), s.Addr().Network())
	return s, nil
}

func parseForwarder(cfg *config.ForwarderConfig) (chain.Hop, error) {
	if cfg == nil {
		return nil, nil
	}

	hc := config.HopConfig{
		Name:     cfg.Name,
		Selector: cfg.Selector,
	}
	if len(cfg.Nodes) > 0 {
		for _, node := range cfg.Nodes {
			if node != nil {
				hc.Nodes = append(hc.Nodes,
					&config.NodeConfig{
						Name:     node.Name,
						Addr:     node.Addr,
						Host:     node.Host,
						Protocol: node.Protocol,
						Bypass:   node.Bypass,
						Bypasses: node.Bypasses,
						HTTP:     node.HTTP,
						TLS:      node.TLS,
						Auth:     node.Auth,
					},
				)
			}
		}
	} else {
		for _, target := range cfg.Targets {
			if v := strings.TrimSpace(target); v != "" {
				hc.Nodes = append(hc.Nodes,
					&config.NodeConfig{
						Name: target,
						Addr: target,
					},
				)
			}
		}
	}

	if len(hc.Nodes) > 0 {
		return ParseHop(&hc)
	}
	return registry.HopRegistry().Get(hc.Name), nil
}

func bypassList(name string, names ...string) []bypass.Bypass {
	var bypasses []bypass.Bypass
	if bp := registry.BypassRegistry().Get(name); bp != nil {
		bypasses = append(bypasses, bp)
	}
	for _, s := range names {
		if bp := registry.BypassRegistry().Get(s); bp != nil {
			bypasses = append(bypasses, bp)
		}
	}
	return bypasses
}

func autherList(name string, names ...string) []auth.Authenticator {
	var authers []auth.Authenticator
	if auther := registry.AutherRegistry().Get(name); auther != nil {
		authers = append(authers, auther)
	}
	for _, s := range names {
		if auther := registry.AutherRegistry().Get(s); auther != nil {
			authers = append(authers, auther)
		}
	}
	return authers
}

func admissionList(name string, names ...string) []admission.Admission {
	var admissions []admission.Admission
	if adm := registry.AdmissionRegistry().Get(name); adm != nil {
		admissions = append(admissions, adm)
	}
	for _, s := range names {
		if adm := registry.AdmissionRegistry().Get(s); adm != nil {
			admissions = append(admissions, adm)
		}
	}

	return admissions
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
		sel = parseChainSelector(group.Selector)
	}
	if len(chains) == 0 {
		return nil
	}

	if sel == nil {
		sel = defaultChainSelector()
	}

	return xchain.NewChainGroup(chains...).
		WithSelector(sel)
}
