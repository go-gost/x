// Package loader converts a parsed [config.Config] into running components
// by parsing each config section and registering the results into the
// global registries. Components are registered in dependency order so that
// when a component reads its dependencies from registries during parsing,
// those dependencies are already available.
package loader

import (
	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/recorder"
	reg "github.com/go-gost/core/registry"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/rewriter"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	admission_parser "github.com/go-gost/x/config/parsing/admission"
	auth_parser "github.com/go-gost/x/config/parsing/auth"
	bypass_parser "github.com/go-gost/x/config/parsing/bypass"
	chain_parser "github.com/go-gost/x/config/parsing/chain"
	hop_parser "github.com/go-gost/x/config/parsing/hop"
	hosts_parser "github.com/go-gost/x/config/parsing/hosts"
	ingress_parser "github.com/go-gost/x/config/parsing/ingress"
	limiter_parser "github.com/go-gost/x/config/parsing/limiter"
	logger_parser "github.com/go-gost/x/config/parsing/logger"
	observer_parser "github.com/go-gost/x/config/parsing/observer"
	quota_parser "github.com/go-gost/x/config/parsing/quota"
	recorder_parser "github.com/go-gost/x/config/parsing/recorder"
	resolver_parser "github.com/go-gost/x/config/parsing/resolver"
	rewriter_parser "github.com/go-gost/x/config/parsing/rewriter"
	router_parser "github.com/go-gost/x/config/parsing/router"
	sd_parser "github.com/go-gost/x/config/parsing/sd"
	service_parser "github.com/go-gost/x/config/parsing/service"
	quota "github.com/go-gost/x/limiter/quota"
	"github.com/go-gost/x/registry"
)

// defaultLoader is a singleton loader used by the top-level Load function.
var (
	defaultLoader *loader = &loader{}
)

// Load parses all config sections from cfg and registers the resulting
// components into the global registries, then sets up the default logger
// and TLS config.
func Load(cfg *config.Config) error {
	return defaultLoader.Load(cfg)
}

// loader holds no state; its Load method is the entry point for converting
// a config into running components.
type loader struct{}

// Load builds the default TLS config, registers all named components from
// cfg into the global registries, and sets the default logger and TLS config.
func (l *loader) Load(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	logCfg := cfg.Log
	if logCfg == nil {
		logCfg = &config.LogConfig{}
	}
	logger.SetDefault(logger_parser.ParseLogger(&config.LoggerConfig{Log: logCfg}))

	tlsCfg, err := parsing.BuildDefaultTLSConfig(cfg.TLS)
	if err != nil {
		return err
	}

	parsing.SetDefaultTLSConfig(tlsCfg)

	if err := register(cfg); err != nil {
		return err
	}

	return nil
}

// named is a generic name+value pair used to buffer parsed components
// before registering them.
type named[T any] struct {
	name string
	v    T
}

// registerGroup replaces all entries in r with the given entries. Old entries
// are unregistered first (see unregisterAll); if any new entry fails to
// register, the group is left partially updated (matching the historical
// reload behavior for intra-group failures).
func registerGroup[T any](entries []named[T], r reg.Registry[T]) error {
	unregisterAll(r)
	for _, e := range entries {
		if err := r.Register(e.name, e.v); err != nil {
			return err
		}
	}
	return nil
}

// unregisterAll removes every entry from r. registry.Unregister closes a value
// before deleting it when it implements io.Closer, so for services this frees
// the bound port (a service's Close closes its listener).
func unregisterAll[T any](r reg.Registry[T]) {
	for name := range r.GetAll() {
		r.Unregister(name)
	}
}

// register parses config sections and registers them into the global
// registries. Groups are processed in dependency order: leaf components
// first, then hops, chains, and finally services. This ensures that
// when a component reads its dependencies from registries during
// parsing, those dependencies are already registered.
func register(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	// --- leaf components (no inter-group registry dependencies) ---

	{
		var entries []named[logger.Logger]
		for _, c := range cfg.Loggers {
			entries = append(entries, named[logger.Logger]{c.Name, logger_parser.ParseLogger(c)})
		}
		if err := registerGroup(entries, registry.LoggerRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[auth.Authenticator]
		for _, c := range cfg.Authers {
			entries = append(entries, named[auth.Authenticator]{c.Name, auth_parser.ParseAuther(c)})
		}
		if err := registerGroup(entries, registry.AutherRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[admission.Admission]
		for _, c := range cfg.Admissions {
			entries = append(entries, named[admission.Admission]{c.Name, admission_parser.ParseAdmission(c)})
		}
		if err := registerGroup(entries, registry.AdmissionRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[bypass.Bypass]
		for _, c := range cfg.Bypasses {
			entries = append(entries, named[bypass.Bypass]{c.Name, bypass_parser.ParseBypass(c)})
		}
		if err := registerGroup(entries, registry.BypassRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[resolver.Resolver]
		for _, c := range cfg.Resolvers {
			r, err := resolver_parser.ParseResolver(c)
			if err != nil {
				return err
			}
			entries = append(entries, named[resolver.Resolver]{c.Name, r})
		}
		if err := registerGroup(entries, registry.ResolverRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[hosts.HostMapper]
		for _, c := range cfg.Hosts {
			entries = append(entries, named[hosts.HostMapper]{c.Name, hosts_parser.ParseHostMapper(c)})
		}
		if err := registerGroup(entries, registry.HostsRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[ingress.Ingress]
		for _, c := range cfg.Ingresses {
			entries = append(entries, named[ingress.Ingress]{c.Name, ingress_parser.ParseIngress(c)})
		}
		if err := registerGroup(entries, registry.IngressRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[router.Router]
		for _, c := range cfg.Routers {
			entries = append(entries, named[router.Router]{c.Name, router_parser.ParseRouter(c)})
		}
		if err := registerGroup(entries, registry.RouterRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[sd.SD]
		for _, c := range cfg.SDs {
			entries = append(entries, named[sd.SD]{c.Name, sd_parser.ParseSD(c)})
		}
		if err := registerGroup(entries, registry.SDRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[observer.Observer]
		for _, c := range cfg.Observers {
			entries = append(entries, named[observer.Observer]{c.Name, observer_parser.ParseObserver(c)})
		}
		if err := registerGroup(entries, registry.ObserverRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[recorder.Recorder]
		for _, c := range cfg.Recorders {
			entries = append(entries, named[recorder.Recorder]{c.Name, recorder_parser.ParseRecorder(c)})
		}
		if err := registerGroup(entries, registry.RecorderRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[rewriter.Rewriter]
		for _, c := range cfg.Rewriters {
			entries = append(entries, named[rewriter.Rewriter]{c.Name, rewriter_parser.ParseRewriter(c)})
		}
		if err := registerGroup(entries, registry.RewriterRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[traffic.TrafficLimiter]
		for _, c := range cfg.Limiters {
			entries = append(entries, named[traffic.TrafficLimiter]{c.Name, limiter_parser.ParseTrafficLimiter(c)})
		}
		if err := registerGroup(entries, registry.TrafficLimiterRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[*quota.Limiter]
		for _, c := range cfg.Quotas {
			entries = append(entries, named[*quota.Limiter]{c.Name, quota_parser.ParseQuotaLimiter(c)})
		}
		if err := registerGroup(entries, registry.QuotaLimiterRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[conn.ConnLimiter]
		for _, c := range cfg.CLimiters {
			entries = append(entries, named[conn.ConnLimiter]{c.Name, limiter_parser.ParseConnLimiter(c)})
		}
		if err := registerGroup(entries, registry.ConnLimiterRegistry()); err != nil {
			return err
		}
	}

	{
		var entries []named[rate.RateLimiter]
		for _, c := range cfg.RLimiters {
			entries = append(entries, named[rate.RateLimiter]{c.Name, limiter_parser.ParseRateLimiter(c)})
		}
		if err := registerGroup(entries, registry.RateLimiterRegistry()); err != nil {
			return err
		}
	}

	// --- hops (references bypasses, resolvers, hosts from registries) ---

	{
		var entries []named[hop.Hop]
		for _, c := range cfg.Hops {
			h, err := hop_parser.ParseHop(c, logger.Default())
			if err != nil {
				return err
			}
			entries = append(entries, named[hop.Hop]{c.Name, h})
		}
		if err := registerGroup(entries, registry.HopRegistry()); err != nil {
			return err
		}
	}

	// --- chains (references hops from registries) ---

	{
		var entries []named[chain.Chainer]
		for _, c := range cfg.Chains {
			ch, err := chain_parser.ParseChain(c, logger.Default())
			if err != nil {
				return err
			}
			entries = append(entries, named[chain.Chainer]{c.Name, ch})
		}
		if err := registerGroup(entries, registry.ChainRegistry()); err != nil {
			return err
		}
	}

	// --- services (references chains, resolvers, hosts, recorders,
	//     limiters, observers, hops from registries) ---
	//
	// Services are the only component group whose construction binds a port:
	// service_parser.ParseService calls listener.Init, which binds. The generic
	// registerGroup "parse-all-then-swap" sequence used by the other groups
	// would therefore bind every new listener while the old services are still
	// listening, causing EADDRINUSE on SIGHUP reload (issue #754, regressed by
	// 82e7e50). Instead, unregister all old services first — unregisterAll
	// closes each one (a service implements io.Closer), freeing its port —
	// then parse, bind, and register the new ones.
	//
	// Trade-off: a parse error in the loop below leaves the registry partially
	// updated (the old services are already closed and only the services parsed
	// before the failure are registered). The construct/bind split would be
	// needed for atomic reload, but this restores the pre-82e7e50 behavior.
	{
		unregisterAll(registry.ServiceRegistry())

		for _, c := range cfg.Services {
			svc, err := service_parser.ParseService(c)
			if err != nil {
				return err
			}
			if svc != nil {
				if err := registry.ServiceRegistry().Register(c.Name, svc); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
