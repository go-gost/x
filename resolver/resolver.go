package resolver

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	resolverpkg "github.com/go-gost/core/resolver"
	resolver_util "github.com/go-gost/x/internal/util/resolver"
	"github.com/go-gost/x/resolver/exchanger"
	"github.com/miekg/dns"
	"google.golang.org/grpc"
)

type NameServer struct {
	Addr      string
	Chain     chain.Chainer
	TTL       time.Duration
	Timeout   time.Duration
	ClientIP  net.IP
	Prefer    string
	Hostname  string // for TLS handshake verification
	exchanger exchanger.Exchanger
}

type options struct {
	domain string
	client *grpc.ClientConn
	logger logger.Logger
}

type Option func(opts *options)

func DomainOption(domain string) Option {
	return func(opts *options) {
		opts.domain = domain
	}
}

func PluginConnOption(c *grpc.ClientConn) Option {
	return func(opts *options) {
		opts.client = c
	}
}

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type resolver struct {
	servers []NameServer
	cache   *resolver_util.Cache
	options options
}

func NewResolver(nameservers []NameServer, opts ...Option) (resolverpkg.Resolver, error) {
	options := options{}
	for _, opt := range opts {
		opt(&options)
	}

	var servers []NameServer
	for _, server := range nameservers {
		addr := strings.TrimSpace(server.Addr)
		if addr == "" {
			continue
		}
		ex, err := exchanger.NewExchanger(
			addr,
			exchanger.RouterOption(
				chain.NewRouter(
					chain.ChainRouterOption(server.Chain),
					chain.LoggerRouterOption(options.logger),
				),
			),
			exchanger.TimeoutOption(server.Timeout),
			exchanger.LoggerOption(options.logger),
		)
		if err != nil {
			options.logger.Warnf("parse %s: %v", server, err)
			continue
		}

		server.exchanger = ex
		servers = append(servers, server)
	}
	cache := resolver_util.NewCache().
		WithLogger(options.logger)

	return &resolver{
		servers: servers,
		cache:   cache,
		options: options,
	}, nil
}

func (r *resolver) Resolve(ctx context.Context, network, host string) (ips []net.IP, err error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if r.options.domain != "" &&
		!strings.Contains(host, ".") {
		host = host + "." + r.options.domain
	}

	for _, server := range r.servers {
		ips, err = r.resolve(ctx, &server, host)
		if err != nil {
			r.options.logger.Error(err)
			continue
		}

		r.options.logger.Debugf("resolve %s via %s: %v", host, server.exchanger.String(), ips)

		if len(ips) > 0 {
			break
		}
	}

	return
}

func (r *resolver) resolve(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	if server == nil {
		return
	}

	if server.Prefer == "ipv6" { // prefer ipv6
		if ips, err = r.resolve6(ctx, server, host); len(ips) > 0 {
			return
		}
		return r.resolve4(ctx, server, host)
	}

	if ips, err = r.resolve4(ctx, server, host); len(ips) > 0 {
		return
	}
	return r.resolve6(ctx, server, host)
}

func (r *resolver) resolve4(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	mq := dns.Msg{}
	mq.SetQuestion(dns.Fqdn(host), dns.TypeA)
	return r.resolveIPs(ctx, server, &mq)
}

func (r *resolver) resolve6(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	mq := dns.Msg{}
	mq.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	return r.resolveIPs(ctx, server, &mq)
}

func (r *resolver) resolveIPs(ctx context.Context, server *NameServer, mq *dns.Msg) (ips []net.IP, err error) {
	key := resolver_util.NewCacheKey(&mq.Question[0])
	mr, ttl := r.cache.Load(key)
	if ttl <= 0 {
		resolver_util.AddSubnetOpt(mq, server.ClientIP)
		mr, err = r.exchange(ctx, server.exchanger, mq)
		if err != nil {
			return
		}
		r.cache.Store(key, mr, server.TTL)
	}

	for _, ans := range mr.Answer {
		if ar, _ := ans.(*dns.AAAA); ar != nil {
			ips = append(ips, ar.AAAA)
		}
		if ar, _ := ans.(*dns.A); ar != nil {
			ips = append(ips, ar.A)
		}
	}

	return
}

func (r *resolver) exchange(ctx context.Context, ex exchanger.Exchanger, mq *dns.Msg) (mr *dns.Msg, err error) {
	query, err := mq.Pack()
	if err != nil {
		return
	}
	reply, err := ex.Exchange(ctx, query)
	if err != nil {
		return
	}

	mr = &dns.Msg{}
	err = mr.Unpack(reply)

	return
}
