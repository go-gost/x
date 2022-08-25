package parsing

import (
	"strings"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/service"
	"github.com/go-gost/x/config"
	tls_util "github.com/go-gost/x/internal/util/tls"
	"github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
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

	admissions := admissionList(cfg.Admission, cfg.Admissions...)

	ln := registry.ListenerRegistry().Get(cfg.Listener.Type)(
		listener.AddrOption(cfg.Addr),
		listener.AutherOption(auth.AuthenticatorList(authers...)),
		listener.AuthOption(parseAuth(cfg.Listener.Auth)),
		listener.TLSConfigOption(tlsConfig),
		listener.AdmissionOption(admission.AdmissionList(admissions...)),
		listener.ChainOption(registry.ChainRegistry().Get(cfg.Listener.Chain)),
		listener.LoggerOption(listenerLogger),
		listener.ServiceOption(cfg.Name),
	)

	if cfg.Listener.Metadata == nil {
		cfg.Listener.Metadata = make(map[string]any)
	}
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

	var sockOpts *chain.SockOpts
	if cfg.SockOpts != nil {
		sockOpts = &chain.SockOpts{
			Mark: cfg.SockOpts.Mark,
		}
	}

	var recorders []recorder.RecorderObject
	for _, r := range cfg.Recorders {
		recorders = append(recorders, recorder.RecorderObject{
			Recorder: registry.RecorderRegistry().Get(r.Name),
			Record:   r.Record,
		})
	}
	router := (&chain.Router{}).
		WithRetries(cfg.Handler.Retries).
		// WithTimeout(timeout time.Duration).
		WithInterface(cfg.Interface).
		WithSockOpts(sockOpts).
		WithChain(registry.ChainRegistry().Get(cfg.Handler.Chain)).
		WithResolver(registry.ResolverRegistry().Get(cfg.Resolver)).
		WithHosts(registry.HostsRegistry().Get(cfg.Hosts)).
		WithRecorder(recorders...).
		WithLogger(handlerLogger)

	h := registry.HandlerRegistry().Get(cfg.Handler.Type)(
		handler.RouterOption(router),
		handler.AutherOption(auth.AuthenticatorList(authers...)),
		handler.AuthOption(parseAuth(cfg.Handler.Auth)),
		handler.BypassOption(bypass.BypassList(bypassList(cfg.Bypass, cfg.Bypasses...)...)),
		handler.TLSConfigOption(tlsConfig),
		handler.LoggerOption(handlerLogger),
	)

	if forwarder, ok := h.(handler.Forwarder); ok {
		forwarder.Forward(parseForwarder(cfg.Forwarder))
	}

	if cfg.Handler.Metadata == nil {
		cfg.Handler.Metadata = make(map[string]any)
	}
	if err := h.Init(metadata.NewMetadata(cfg.Handler.Metadata)); err != nil {
		handlerLogger.Error("init: ", err)
		return nil, err
	}

	s := service.NewService(cfg.Name, ln, h,
		service.AdmissionOption(admission.AdmissionList(admissions...)),
		service.LoggerOption(serviceLogger),
	)

	serviceLogger.Infof("listening on %s/%s", s.Addr().String(), s.Addr().Network())
	return s, nil
}

func parseForwarder(cfg *config.ForwarderConfig) *chain.NodeGroup {
	if cfg == nil ||
		(len(cfg.Targets) == 0 && len(cfg.Nodes) == 0) {
		return nil
	}

	group := &chain.NodeGroup{}
	if len(cfg.Nodes) > 0 {
		for _, node := range cfg.Nodes {
			if node != nil {
				group.AddNode(&chain.Node{
					Name:   node.Name,
					Addr:   node.Addr,
					Bypass: bypass.BypassList(bypassList(node.Bypass, node.Bypasses...)...),
					Marker: &chain.FailMarker{},
				})
			}
		}
	} else {
		for _, target := range cfg.Targets {
			if v := strings.TrimSpace(target); v != "" {
				group.AddNode(&chain.Node{
					Name:   target,
					Addr:   target,
					Marker: &chain.FailMarker{},
				})
			}
		}
	}

	return group.WithSelector(parseSelector(cfg.Selector))
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
