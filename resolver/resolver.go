// Package resolver implements DNS resolution via configurable nameservers
// with caching, async lookup, and IPv4/IPv6 preference support.
package resolver

import (
	"context"
	"fmt"
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
	"golang.org/x/sync/singleflight"
)

// NameServer describes a DNS nameserver configuration including its address,
// optional upstream chain, TTL, timeout, EDNS0 client subnet, and IP preference.
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

// Option is a functional option for the resolver.
type Option func(opts *options)

// DomainOption sets the default domain suffix appended to single-label hostnames.
func DomainOption(domain string) Option {
	return func(opts *options) {
		opts.domain = domain
	}
}

// LoggerOption sets the logger for the resolver.
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

const (
	maxAsyncRefresh = 32 // max concurrent background refresh goroutines

	preferIPv4 = "ipv4"
	preferIPv6 = "ipv6"
)

// localResolver resolves hostnames via DNS using configured nameservers and a cache.
type localResolver struct {
	servers    []NameServer
	cache      *resolver_util.Cache
	options    options
	refreshSem chan struct{}   // bounds concurrent async refresh goroutines
	sfGroup    singleflight.Group
}

// NewResolver creates a Resolver that queries the given nameservers in order,
// with DNS caching and optional async background refresh.
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
		case "ip4", "ipv4":
			server.Only = preferIPv4
			server.Prefer = preferIPv4
		case "ip6", "ipv6":
			server.Only = preferIPv6
			server.Prefer = preferIPv6
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
		servers:    servers,
		cache:      cache,
		options:    options,
		refreshSem: make(chan struct{}, maxAsyncRefresh),
	}, nil
}

// callerNetworkPref maps the caller's network hint to a DNS query preference.
// Returns "ipv4" for "ip4", "ipv6" for "ip6", or "" for no preference.
func callerNetworkPref(network string) string {
	switch network {
	case "ip4":
		return preferIPv4
	case "ip6":
		return preferIPv6
	default:
		return ""
	}
}

func (r *localResolver) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) (ips []net.IP, err error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if r.options.domain != "" &&
		!strings.Contains(host, ".") {
		host = host + "." + r.options.domain
	}

	callerPref := callerNetworkPref(network)

	for _, server := range r.servers {
		if server.Async {
			ips, err = r.resolveAsync(ctx, &server, host, callerPref)
		} else {
			ips, err = r.resolve(ctx, &server, host, callerPref)
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

// resolvePreference determines the effective IP preference.
// Precedence: server.Only (hard constraint) > callerPref > server.Prefer > default (ipv4-first).
func resolvePreference(server *NameServer, callerPref string) string {
	if server.Only != "" {
		return server.Only
	}
	if callerPref != "" {
		return callerPref
	}
	if server.Prefer != "" {
		return server.Prefer
	}
	return ""
}

// shouldReturn reports whether results from the given address family should be
// accepted without falling back to the other family. Returns true when results
// were found, or when a hard constraint (Only or caller network) pins to this family.
func shouldReturn(ips []net.IP, server *NameServer, callerPref, family string) bool {
	return len(ips) > 0 || server.Only == family || callerPref == family
}

func (r *localResolver) resolve(ctx context.Context, server *NameServer, host string, callerPref string) (ips []net.IP, err error) {
	if server == nil {
		return
	}

	pref := resolvePreference(server, callerPref)

	if pref == preferIPv6 {
		if ips, err = r.resolve6(ctx, server, host); shouldReturn(ips, server, callerPref, preferIPv6) {
			return
		}
		return r.resolve4(ctx, server, host)
	}

	if ips, err = r.resolve4(ctx, server, host); shouldReturn(ips, server, callerPref, preferIPv4) {
		return
	}
	return r.resolve6(ctx, server, host)
}

func (r *localResolver) resolveAsync(ctx context.Context, server *NameServer, host string, callerPref string) (ips []net.IP, err error) {
	ips, ttl, ok := r.lookupCache(ctx, server, host, callerPref)
	if !ok {
		return r.resolve(ctx, server, host, callerPref)
	}

	if ttl <= 0 {
		r.options.logger.Debugf("async resolve %s via %s", host, server.exchanger.String())
		select {
		case r.refreshSem <- struct{}{}:
			go func() {
				defer func() { <-r.refreshSem }()
				r.resolve(context.WithoutCancel(ctx), server, host, callerPref)
			}()
		default:
			r.options.logger.Debugf("async refresh skipped: semaphore full for %s", host)
		}
	}
	return
}

func (r *localResolver) lookupCache(ctx context.Context, server *NameServer, host string, callerPref string) (ips []net.IP, ttl time.Duration, ok bool) {
	lookup := func(t uint16, host string) (ips []net.IP, ttl time.Duration, ok bool) {
		mq := dns.Msg{}
		mq.SetQuestion(dns.Fqdn(host), t)
		mr, ttl := r.cache.Load(ctx, resolver_util.NewCacheKey(&mq.Question[0]))
		if mr == nil {
			return
		}
		ok = true
		ips = extractIPs(mr)
		return
	}

	pref := resolvePreference(server, callerPref)

	if pref == preferIPv6 {
		ips, ttl, ok = lookup(dns.TypeAAAA, host)
		if shouldReturn(ips, server, callerPref, preferIPv6) {
			return
		}
		ips, ttl, ok = lookup(dns.TypeA, host)
		return
	}

	ips, ttl, ok = lookup(dns.TypeA, host)
	if shouldReturn(ips, server, callerPref, preferIPv4) {
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

	result, err, _ := r.sfGroup.Do(string(key), func() (any, error) {
		// Double-check cache after winning the singleflight race.
		mr, ttl := r.cache.Load(ctx, key)
		if ttl > 0 {
			return mr, nil
		}

		// Apply EDNS0 subnet option before exchange. mq is fresh per resolve4/resolve6
		// call, so mutation is safe — it will not be shared across singleflight callers.
		resolver_util.AddSubnetOpt(mq, server.ClientIP)
		mr, err := r.exchange(ctx, server.exchanger, mq)
		if err != nil {
			return nil, err
		}
		r.cache.Store(ctx, key, mr, server.TTL)

		if r.options.logger.IsLevelEnabled(logger.TraceLevel) {
			r.options.logger.Trace(mr.String())
		}
		return mr, nil
	})
	if err != nil {
		return nil, err
	}

	return extractIPs(result.(*dns.Msg)), nil
}

// extractIPs returns all A and AAAA records from a DNS message.
func extractIPs(mr *dns.Msg) []net.IP {
	if mr == nil {
		return nil
	}
	ips := make([]net.IP, 0, len(mr.Answer))
	for _, ans := range mr.Answer {
		if ar, ok := ans.(*dns.A); ok {
			ips = append(ips, ar.A)
		}
		if ar, ok := ans.(*dns.AAAA); ok {
			ips = append(ips, ar.AAAA)
		}
	}
	return ips
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
	if err = mr.Unpack(reply); err != nil {
		return
	}

	if mr.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS %s for %s", dns.RcodeToString[mr.Rcode], mq.Question[0].Name)
	}

	return
}
