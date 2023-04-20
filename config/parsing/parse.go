package parsing

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/core/selector"
	admission_impl "github.com/go-gost/x/admission"
	auth_impl "github.com/go-gost/x/auth"
	bypass_impl "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/config"
	xhosts "github.com/go-gost/x/hosts"
	xingress "github.com/go-gost/x/ingress"
	"github.com/go-gost/x/internal/loader"
	xconn "github.com/go-gost/x/limiter/conn"
	xrate "github.com/go-gost/x/limiter/rate"
	xtraffic "github.com/go-gost/x/limiter/traffic"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	resolver_impl "github.com/go-gost/x/resolver"
	xs "github.com/go-gost/x/selector"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	mdKeyProxyProtocol = "proxyProtocol"
	mdKeyInterface     = "interface"
	mdKeySoMark        = "so_mark"
	mdKeyHash          = "hash"
	mdKeyPreUp         = "preUp"
	mdKeyPreDown       = "preDown"
	mdKeyPostUp        = "postUp"
	mdKeyPostDown      = "postDown"
	mdKeyIgnoreChain   = "ignoreChain"
)

func ParseAuther(cfg *config.AutherConfig) auth.Authenticator {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
		}
		return auth_impl.NewPluginAuthenticator(
			auth_impl.PluginConnOption(c),
			auth_impl.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":   "auther",
				"auther": cfg.Name,
			})),
		)
	}

	m := make(map[string]string)

	for _, user := range cfg.Auths {
		if user.Username == "" {
			continue
		}
		m[user.Username] = user.Password
	}

	opts := []auth_impl.Option{
		auth_impl.AuthsOption(m),
		auth_impl.ReloadPeriodOption(cfg.Reload),
		auth_impl.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":   "auther",
			"auther": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, auth_impl.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		opts = append(opts, auth_impl.RedisLoaderOption(loader.RedisHashLoader(
			cfg.Redis.Addr,
			loader.DBRedisLoaderOption(cfg.Redis.DB),
			loader.PasswordRedisLoaderOption(cfg.Redis.Password),
			loader.KeyRedisLoaderOption(cfg.Redis.Key),
		)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, auth_impl.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return auth_impl.NewAuthenticator(opts...)
}

func ParseAutherFromAuth(au *config.AuthConfig) auth.Authenticator {
	if au == nil || au.Username == "" {
		return nil
	}
	return auth_impl.NewAuthenticator(
		auth_impl.AuthsOption(
			map[string]string{
				au.Username: au.Password,
			},
		),
		auth_impl.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind": "auther",
		})),
	)
}

func parseAuth(cfg *config.AuthConfig) *url.Userinfo {
	if cfg == nil || cfg.Username == "" {
		return nil
	}

	if cfg.Password == "" {
		return url.User(cfg.Username)
	}
	return url.UserPassword(cfg.Username, cfg.Password)
}

func parseChainSelector(cfg *config.SelectorConfig) selector.Selector[chain.Chainer] {
	if cfg == nil {
		return nil
	}

	var strategy selector.Strategy[chain.Chainer]
	switch cfg.Strategy {
	case "round", "rr":
		strategy = xs.RoundRobinStrategy[chain.Chainer]()
	case "random", "rand":
		strategy = xs.RandomStrategy[chain.Chainer]()
	case "fifo", "ha":
		strategy = xs.FIFOStrategy[chain.Chainer]()
	case "hash":
		strategy = xs.HashStrategy[chain.Chainer]()
	default:
		strategy = xs.RoundRobinStrategy[chain.Chainer]()
	}
	return xs.NewSelector(
		strategy,
		xs.FailFilter[chain.Chainer](cfg.MaxFails, cfg.FailTimeout),
		xs.BackupFilter[chain.Chainer](),
	)
}

func parseNodeSelector(cfg *config.SelectorConfig) selector.Selector[*chain.Node] {
	if cfg == nil {
		return nil
	}

	var strategy selector.Strategy[*chain.Node]
	switch cfg.Strategy {
	case "round", "rr":
		strategy = xs.RoundRobinStrategy[*chain.Node]()
	case "random", "rand":
		strategy = xs.RandomStrategy[*chain.Node]()
	case "fifo", "ha":
		strategy = xs.FIFOStrategy[*chain.Node]()
	case "hash":
		strategy = xs.HashStrategy[*chain.Node]()
	default:
		strategy = xs.RoundRobinStrategy[*chain.Node]()
	}

	return xs.NewSelector(
		strategy,
		xs.FailFilter[*chain.Node](cfg.MaxFails, cfg.FailTimeout),
		xs.BackupFilter[*chain.Node](),
	)
}

func ParseAdmission(cfg *config.AdmissionConfig) admission.Admission {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
		}
		return admission_impl.NewPluginAdmission(
			admission_impl.PluginConnOption(c),
			admission_impl.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":      "admission",
				"admission": cfg.Name,
			})),
		)
	}

	opts := []admission_impl.Option{
		admission_impl.MatchersOption(cfg.Matchers),
		admission_impl.WhitelistOption(cfg.Reverse || cfg.Whitelist),
		admission_impl.ReloadPeriodOption(cfg.Reload),
		admission_impl.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":      "admission",
			"admission": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, admission_impl.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		opts = append(opts, admission_impl.RedisLoaderOption(loader.RedisSetLoader(
			cfg.Redis.Addr,
			loader.DBRedisLoaderOption(cfg.Redis.DB),
			loader.PasswordRedisLoaderOption(cfg.Redis.Password),
			loader.KeyRedisLoaderOption(cfg.Redis.Key),
		)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, admission_impl.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}

	return admission_impl.NewAdmission(opts...)
}

func ParseBypass(cfg *config.BypassConfig) bypass.Bypass {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
		}
		return bypass_impl.NewPluginBypass(
			bypass_impl.PluginConnOption(c),
			bypass_impl.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":   "bypass",
				"bypass": cfg.Name,
			})),
		)
	}

	opts := []bypass_impl.Option{
		bypass_impl.MatchersOption(cfg.Matchers),
		bypass_impl.WhitelistOption(cfg.Reverse || cfg.Whitelist),
		bypass_impl.ReloadPeriodOption(cfg.Reload),
		bypass_impl.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, bypass_impl.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		opts = append(opts, bypass_impl.RedisLoaderOption(loader.RedisSetLoader(
			cfg.Redis.Addr,
			loader.DBRedisLoaderOption(cfg.Redis.DB),
			loader.PasswordRedisLoaderOption(cfg.Redis.Password),
			loader.KeyRedisLoaderOption(cfg.Redis.Key),
		)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, bypass_impl.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}

	return bypass_impl.NewBypass(opts...)
}

func ParseResolver(cfg *config.ResolverConfig) (resolver.Resolver, error) {
	if cfg == nil {
		return nil, nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
			return nil, err
		}
		return resolver_impl.NewPluginResolver(
			resolver_impl.PluginConnOption(c),
			resolver_impl.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":     "resolver",
				"resolver": cfg.Name,
			})),
		)
	}

	var nameservers []resolver_impl.NameServer
	for _, server := range cfg.Nameservers {
		nameservers = append(nameservers, resolver_impl.NameServer{
			Addr:     server.Addr,
			Chain:    registry.ChainRegistry().Get(server.Chain),
			TTL:      server.TTL,
			Timeout:  server.Timeout,
			ClientIP: net.ParseIP(server.ClientIP),
			Prefer:   server.Prefer,
			Hostname: server.Hostname,
		})
	}

	return resolver_impl.NewResolver(
		nameservers,
		resolver_impl.LoggerOption(
			logger.Default().WithFields(map[string]any{
				"kind":     "resolver",
				"resolver": cfg.Name,
			}),
		),
	)
}

func ParseHosts(cfg *config.HostsConfig) hosts.HostMapper {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
		}
		return xhosts.NewPluginHostMapper(
			xhosts.PluginConnOption(c),
			xhosts.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":  "hosts",
				"hosts": cfg.Name,
			})),
		)
	}

	var mappings []xhosts.Mapping
	for _, mapping := range cfg.Mappings {
		if mapping.IP == "" || mapping.Hostname == "" {
			continue
		}

		ip := net.ParseIP(mapping.IP)
		if ip == nil {
			continue
		}
		mappings = append(mappings, xhosts.Mapping{
			Hostname: mapping.Hostname,
			IP:       ip,
		})
	}
	opts := []xhosts.Option{
		xhosts.MappingsOption(mappings),
		xhosts.ReloadPeriodOption(cfg.Reload),
		xhosts.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":  "hosts",
			"hosts": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xhosts.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xhosts.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xhosts.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xhosts.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xhosts.NewHostMapper(opts...)
}

func ParseIngress(cfg *config.IngressConfig) ingress.Ingress {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
		}
		return xingress.NewPluginIngress(
			xingress.PluginConnOption(c),
			xingress.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":    "ingress",
				"ingress": cfg.Name,
			})),
		)
	}

	var rules []xingress.Rule
	for _, rule := range cfg.Rules {
		if rule.Hostname == "" || rule.Endpoint == "" {
			continue
		}

		rules = append(rules, xingress.Rule{
			Hostname: rule.Hostname,
			Endpoint: rule.Endpoint,
		})
	}
	opts := []xingress.Option{
		xingress.RulesOption(rules),
		xingress.ReloadPeriodOption(cfg.Reload),
		xingress.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "ingress",
			"ingress": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xingress.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "set": // redis set
			opts = append(opts, xingress.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis hash
			opts = append(opts, xingress.RedisLoaderOption(loader.RedisHashLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xingress.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xingress.NewIngress(opts...)
}

func ParseRecorder(cfg *config.RecorderConfig) (r recorder.Recorder) {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		c, err := newPluginConn(cfg.Plugin)
		if err != nil {
			logger.Default().Error(err)
		}
		return xrecorder.NewPluginRecorder(
			xrecorder.PluginConnOption(c),
			xrecorder.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":     "recorder",
				"recorder": cfg.Name,
			})),
		)
	}

	if cfg.File != nil && cfg.File.Path != "" {
		return xrecorder.FileRecorder(cfg.File.Path,
			xrecorder.SepRecorderOption(cfg.File.Sep),
		)
	}

	if cfg.Redis != nil &&
		cfg.Redis.Addr != "" &&
		cfg.Redis.Key != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			return xrecorder.RedisListRecorder(cfg.Redis.Addr,
				xrecorder.DBRedisRecorderOption(cfg.Redis.DB),
				xrecorder.KeyRedisRecorderOption(cfg.Redis.Key),
				xrecorder.PasswordRedisRecorderOption(cfg.Redis.Password),
			)
		case "sset": // sorted set
			return xrecorder.RedisSortedSetRecorder(cfg.Redis.Addr,
				xrecorder.DBRedisRecorderOption(cfg.Redis.DB),
				xrecorder.KeyRedisRecorderOption(cfg.Redis.Key),
				xrecorder.PasswordRedisRecorderOption(cfg.Redis.Password),
			)
		default: // redis set
			return xrecorder.RedisSetRecorder(cfg.Redis.Addr,
				xrecorder.DBRedisRecorderOption(cfg.Redis.DB),
				xrecorder.KeyRedisRecorderOption(cfg.Redis.Key),
				xrecorder.PasswordRedisRecorderOption(cfg.Redis.Password),
			)
		}
	}

	return
}

func defaultNodeSelector() selector.Selector[*chain.Node] {
	return xs.NewSelector(
		xs.RoundRobinStrategy[*chain.Node](),
		xs.FailFilter[*chain.Node](xs.DefaultMaxFails, xs.DefaultFailTimeout),
		xs.BackupFilter[*chain.Node](),
	)
}

func defaultChainSelector() selector.Selector[chain.Chainer] {
	return xs.NewSelector(
		xs.RoundRobinStrategy[chain.Chainer](),
		xs.FailFilter[chain.Chainer](xs.DefaultMaxFails, xs.DefaultFailTimeout),
		xs.BackupFilter[chain.Chainer](),
	)
}

func ParseTrafficLimiter(cfg *config.LimiterConfig) (lim traffic.TrafficLimiter) {
	if cfg == nil {
		return nil
	}

	var opts []xtraffic.Option

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xtraffic.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xtraffic.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xtraffic.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xtraffic.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	opts = append(opts,
		xtraffic.LimitsOption(cfg.Limits...),
		xtraffic.ReloadPeriodOption(cfg.Reload),
		xtraffic.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": cfg.Name,
		})),
	)

	return xtraffic.NewTrafficLimiter(opts...)
}

func ParseConnLimiter(cfg *config.LimiterConfig) (lim conn.ConnLimiter) {
	if cfg == nil {
		return nil
	}

	var opts []xconn.Option

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xconn.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xconn.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xconn.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xconn.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	opts = append(opts,
		xconn.LimitsOption(cfg.Limits...),
		xconn.ReloadPeriodOption(cfg.Reload),
		xconn.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": cfg.Name,
		})),
	)

	return xconn.NewConnLimiter(opts...)
}

func ParseRateLimiter(cfg *config.LimiterConfig) (lim rate.RateLimiter) {
	if cfg == nil {
		return nil
	}

	var opts []xrate.Option

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xrate.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		switch cfg.Redis.Type {
		case "list": // redis list
			opts = append(opts, xrate.RedisLoaderOption(loader.RedisListLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		default: // redis set
			opts = append(opts, xrate.RedisLoaderOption(loader.RedisSetLoader(
				cfg.Redis.Addr,
				loader.DBRedisLoaderOption(cfg.Redis.DB),
				loader.PasswordRedisLoaderOption(cfg.Redis.Password),
				loader.KeyRedisLoaderOption(cfg.Redis.Key),
			)))
		}
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xrate.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	opts = append(opts,
		xrate.LimitsOption(cfg.Limits...),
		xrate.ReloadPeriodOption(cfg.Reload),
		xrate.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": cfg.Name,
		})),
	)

	return xrate.NewRateLimiter(opts...)
}

func newPluginConn(cfg *config.PluginConfig) (*grpc.ClientConn, error) {
	grpcOpts := []grpc.DialOption{
		// grpc.WithBlock(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.DefaultConfig,
		}),
		grpc.FailOnNonTempDialError(true),
	}
	if tlsCfg := cfg.TLS; tlsCfg != nil && tlsCfg.Secure {
		grpcOpts = append(grpcOpts,
			grpc.WithAuthority(tlsCfg.ServerName),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				ServerName:         tlsCfg.ServerName,
				InsecureSkipVerify: !tlsCfg.Secure,
			})))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if cfg.Token != "" {
		grpcOpts = append(grpcOpts, grpc.WithPerRPCCredentials(&rpcCredentials{token: cfg.Token}))
	}
	return grpc.Dial(cfg.Addr, grpcOpts...)
}

type rpcCredentials struct {
	token string
}

func (c *rpcCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"token": c.token,
	}, nil
}

func (c *rpcCredentials) RequireTransportSecurity() bool {
	return false
}
