package dashboard

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/resolver"
)

// observe records one call and its latency. The nil check keeps callers from
// branching when a set returns nothing (it never does, but it is cheap).
func (c *moduleCounters) observe(start time.Time) {
	if c == nil {
		return
	}
	c.calls.Add(1)
	if d := time.Since(start).Microseconds(); d > 0 {
		c.latencySum.Add(uint64(d))
	}
	c.latencyCount.Add(1)
}

func (c *moduleCounters) hit() {
	if c != nil {
		c.hits.Add(1)
	}
}

func (c *moduleCounters) miss() {
	if c != nil {
		c.misses.Add(1)
	}
}

func (c *moduleCounters) fail() {
	if c != nil {
		c.errors.Add(1)
	}
}

type bypassWrapper struct {
	next bypass.Bypass
	set  *seriesSet
}

// WrapBypass instruments a bypass rule. It returns next unchanged when the
// dashboard is disabled.
func WrapBypass(name string, next bypass.Bypass) bypass.Bypass {
	if !Enabled() || next == nil {
		return next
	}
	return &bypassWrapper{next: next, set: newSeriesSet("bypass", name)}
}

func (w *bypassWrapper) IsWhitelist() bool { return w.next.IsWhitelist() }

func (w *bypassWrapper) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	var o bypass.Options
	if len(opts) > 0 {
		for _, opt := range opts {
			opt(&o)
		}
	}

	start := time.Now()
	hit := w.next.Contains(ctx, network, addr, opts...)
	c := w.set.get(o.Service)
	c.observe(start)
	if hit {
		c.hit()
	} else {
		c.miss()
	}
	return hit
}

type admissionWrapper struct {
	next admission.Admission
	set  *seriesSet
}

// WrapAdmission instruments an admission controller. Denied clients count as
// misses; they are policy decisions, not errors.
func WrapAdmission(name string, next admission.Admission) admission.Admission {
	if !Enabled() || next == nil {
		return next
	}
	return &admissionWrapper{next: next, set: newSeriesSet("admission", name)}
}

func (w *admissionWrapper) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	var o admission.Options
	if len(opts) > 0 {
		for _, opt := range opts {
			opt(&o)
		}
	}

	start := time.Now()
	ok := w.next.Admit(ctx, network, addr, opts...)
	c := w.set.get(o.Service)
	c.observe(start)
	if ok {
		c.hit()
	} else {
		c.miss()
	}
	return ok
}

type hostsWrapper struct {
	next hosts.HostMapper
	set  *seriesSet
}

// WrapHosts instruments a host mapper. Hosts are shared by many services, so
// the series has no service dimension.
func WrapHosts(name string, next hosts.HostMapper) hosts.HostMapper {
	if !Enabled() || next == nil {
		return next
	}
	return &hostsWrapper{next: next, set: newSeriesSet("hosts", name)}
}

func (w *hostsWrapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	start := time.Now()
	ips, ok := w.next.Lookup(ctx, network, host, opts...)
	c := w.set.get("")
	c.observe(start)
	if ok {
		c.hit()
	} else {
		c.miss()
	}
	return ips, ok
}

type resolverWrapper struct {
	next resolver.Resolver
	set  *seriesSet
}

// WrapResolver instruments a resolver. A returned error counts as an error;
// an empty result counts as a miss.
func WrapResolver(name string, next resolver.Resolver) resolver.Resolver {
	if !Enabled() || next == nil {
		return next
	}
	return &resolverWrapper{next: next, set: newSeriesSet("resolver", name)}
}

func (w *resolverWrapper) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) ([]net.IP, error) {
	start := time.Now()
	ips, err := w.next.Resolve(ctx, network, host, opts...)
	c := w.set.get("")
	c.observe(start)
	switch {
	case err != nil:
		c.fail()
	case len(ips) == 0:
		c.miss()
	default:
		c.hit()
	}
	return ips, err
}

// Close delegates to the wrapped module. The registry closes values on
// unregister/reload, so a wrapper that hides io.Closer would leak reload
// goroutines and Redis/gRPC clients.
func (w *bypassWrapper) Close() error    { return closeModule(w.next) }
func (w *admissionWrapper) Close() error { return closeModule(w.next) }
func (w *hostsWrapper) Close() error     { return closeModule(w.next) }
func (w *resolverWrapper) Close() error  { return closeModule(w.next) }

func closeModule(v any) error {
	if c, ok := v.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

var (
	_ bypass.Bypass       = (*bypassWrapper)(nil)
	_ io.Closer           = (*bypassWrapper)(nil)
	_ admission.Admission = (*admissionWrapper)(nil)
	_ io.Closer           = (*admissionWrapper)(nil)
	_ hosts.HostMapper    = (*hostsWrapper)(nil)
	_ io.Closer           = (*hostsWrapper)(nil)
	_ resolver.Resolver   = (*resolverWrapper)(nil)
	_ io.Closer           = (*resolverWrapper)(nil)
)
