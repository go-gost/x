package resolver

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/resolver"
	xchain "github.com/go-gost/x/chain"
	resolver_util "github.com/go-gost/x/internal/util/resolver"
	"github.com/go-gost/x/resolver/exchanger"
	"github.com/miekg/dns"
)

type NameServer struct {
	Addr      string
	Chain     chain.Chainer
	TTL       time.Duration
	Timeout   time.Duration
	ClientIP  net.IP
	Prefer    string
	Hostname  string // for TLS handshake verification
	Async     bool
	Only      string
	exchanger exchanger.Exchanger
}

type options struct {
	domain string
	logger logger.Logger
}

type Option func(opts *options)

func DomainOption(domain string) Option {
	return func(opts *options) {
		opts.domain = domain
	}
}

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type localResolver struct {
	servers []NameServer
	cache   *resolver_util.Cache
	options options
}

func NewResolver(nameservers []NameServer, opts ...Option) (resolver.Resolver, error) {
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
				xchain.NewRouter(
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

		switch server.Only {
		case "ip4", "ipv4", "ip6", "ipv6":
			server.Prefer = server.Only
		default:
			server.Only = ""
		}
		if server.TTL < 0 {
			server.Async = false
		}
		servers = append(servers, server)
	}
	cache := resolver_util.NewCache().
		WithLogger(options.logger)

	return &localResolver{
		servers: servers,
		cache:   cache,
		options: options,
	}, nil
}

func (r *localResolver) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) (ips []net.IP, err error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if r.options.domain != "" &&
		!strings.Contains(host, ".") {
		host = host + "." + r.options.domain
	}

	for _, server := range r.servers {
		if server.Async {
			ips, err = r.resolveAsync(ctx, &server, host)
		} else {
			ips, err = r.resolve(ctx, &server, host)
		}
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

func (r *localResolver) resolve(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	if server == nil {
		return
	}

	if server.Prefer == "ipv6" { // prefer ipv6
		if ips, err = r.resolve6(ctx, server, host); len(ips) > 0 || server.Only == "ipv6" {
			return
		}
		return r.resolve4(ctx, server, host)
	}

	if ips, err = r.resolve4(ctx, server, host); len(ips) > 0 || server.Only == "ipv4" {
		return
	}
	return r.resolve6(ctx, server, host)
}

func (r *localResolver) resolveAsync(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	ips, ttl, ok := r.lookupCache(ctx, server, host)
	if !ok {
		return r.resolve(ctx, server, host)
	}

	if ttl <= 0 {
		r.options.logger.Debugf("async resolve %s via %s", host, server.exchanger.String())
		go r.resolve(ctx, server, host)
	}
	return
}

func (r *localResolver) lookupCache(ctx context.Context, server *NameServer, host string) (ips []net.IP, ttl time.Duration, ok bool) {
	lookup := func(t uint16, host string) (ips []net.IP, ttl time.Duration, ok bool) {
		mq := dns.Msg{}
		mq.SetQuestion(dns.Fqdn(host), t)
		mr, ttl := r.cache.Load(ctx, resolver_util.NewCacheKey(&mq.Question[0]))
		if mr == nil {
			return
		}

		ok = true

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

	if server.Prefer == "ipv6" {
		ips, ttl, ok = lookup(dns.TypeAAAA, host)
		if len(ips) > 0 || server.Only == "ipv6" {
			return
		}

		ips, ttl, ok = lookup(dns.TypeA, host)
		return
	}

	ips, ttl, ok = lookup(dns.TypeA, host)
	if len(ips) > 0 || server.Only == "ipv4" {
		return
	}
	return lookup(dns.TypeAAAA, host)
}

func (r *localResolver) resolve4(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	mq := dns.Msg{}
	mq.SetQuestion(dns.Fqdn(host), dns.TypeA)
	return r.resolveIPs(ctx, server, &mq)
}

func (r *localResolver) resolve6(ctx context.Context, server *NameServer, host string) (ips []net.IP, err error) {
	mq := dns.Msg{}
	mq.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	return r.resolveIPs(ctx, server, &mq)
}

func (r *localResolver) resolveIPs(ctx context.Context, server *NameServer, mq *dns.Msg) (ips []net.IP, err error) {
	if r.options.logger.IsLevelEnabled(logger.TraceLevel) {
		r.options.logger.Trace(mq.String())
	}

	key := resolver_util.NewCacheKey(&mq.Question[0])
	mr, ttl := r.cache.Load(ctx, key)
	if ttl <= 0 {
		resolver_util.AddSubnetOpt(mq, server.ClientIP)
		mr, err = r.exchange(ctx, server.exchanger, mq)
		if err != nil {
			return
		}
		r.cache.Store(ctx, key, mr, server.TTL)

		if r.options.logger.IsLevelEnabled(logger.TraceLevel) {
			r.options.logger.Trace(mr.String())
		}
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

func (r *localResolver) exchange(ctx context.Context, ex exchanger.Exchanger, mq *dns.Msg) (mr *dns.Msg, err error) {
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
