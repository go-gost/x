// Package limiter provides a cached traffic limiter that wraps a
// TrafficLimiter with in-memory caching to reduce calls to the underlying
// limiter (e.g., plugin-based limiters).
package limiter

import (
	"context"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/x/internal/util/cache"
)

const (
	defaultRefreshInterval = 30 * time.Second
	defaultCleanupInterval = 60 * time.Second
)

type options struct {
	refreshInterval time.Duration
	cleanupInterval time.Duration
	scope           string
}

// Option configures a cachedTrafficLimiter.
type Option func(*options)

// RefreshIntervalOption sets the cache refresh interval. Cached limiters
// are refreshed after this duration. The minimum value is 1 second.
func RefreshIntervalOption(interval time.Duration) Option {
	return func(o *options) {
		o.refreshInterval = interval
	}
}

// CleanupIntervalOption sets the interval for cleaning up expired cache
// entries. The minimum value is 1 second.
func CleanupIntervalOption(interval time.Duration) Option {
	return func(o *options) {
		o.cleanupInterval = interval
	}
}

// ScopeOption filters cached limiters by scope. When set, only requests
// with a matching scope return a limiter; non-matching scopes return nil.
func ScopeOption(scope string) Option {
	return func(o *options) {
		o.scope = scope
	}
}

type cachedTrafficLimiter struct {
	inLimits  *cache.Cache
	outLimits *cache.Cache
	limiter   traffic.TrafficLimiter
	options   options
}

// NewCachedTrafficLimiter wraps a TrafficLimiter with an in-memory cache.
// Cached limiters are refreshed after the configured refresh interval.
// Returns nil if the inner limiter is nil.
func NewCachedTrafficLimiter(limiter traffic.TrafficLimiter, opts ...Option) traffic.TrafficLimiter {
	if limiter == nil {
		return nil
	}

	var options options
	for _, opt := range opts {
		opt(&options)
	}

	if options.refreshInterval == 0 {
		options.refreshInterval = defaultRefreshInterval
	}
	if options.refreshInterval < time.Second {
		options.refreshInterval = time.Second
	}

	if options.cleanupInterval == 0 {
		options.cleanupInterval = defaultCleanupInterval
	}
	if options.cleanupInterval < time.Second {
		options.cleanupInterval = time.Second
	}

	lim := &cachedTrafficLimiter{
		inLimits:  cache.NewCache(options.cleanupInterval),
		outLimits: cache.NewCache(options.cleanupInterval),
		limiter:   limiter,
		options:   options,
	}
	return lim
}

func (p *cachedTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.limiter == nil {
		return nil
	}

	var options limiter.Options
	for _, opt := range opts {
		opt(&options)
	}

	if p.options.scope != "" && p.options.scope != options.Scope {
		return nil
	}

	item := p.inLimits.Get(key)
	lim, _ := item.Value().(traffic.Limiter)
	if !item.Expired() {
		return lim
	}

	limNew := p.limiter.In(ctx, key, opts...)
	if limNew == nil {
		if lim == nil {
			return nil
		}
		limNew = lim
	}
	if item == nil || !p.equal(lim, limNew) {
		p.inLimits.Set(key, cache.NewItem(limNew, p.options.refreshInterval))
		return limNew
	}

	p.inLimits.Set(key, cache.NewItem(lim, p.options.refreshInterval))

	return lim
}

func (p *cachedTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.limiter == nil {
		return nil
	}

	var options limiter.Options
	for _, opt := range opts {
		opt(&options)
	}

	if p.options.scope != "" && p.options.scope != options.Scope {
		return nil
	}

	item := p.outLimits.Get(key)
	lim, _ := item.Value().(traffic.Limiter)
	if !item.Expired() {
		return lim
	}

	limNew := p.limiter.Out(ctx, key, opts...)
	if limNew == nil {
		if lim == nil {
			return nil
		}
		limNew = lim
	}
	if item == nil || !p.equal(lim, limNew) {
		p.outLimits.Set(key, cache.NewItem(limNew, p.options.refreshInterval))
		return limNew
	}

	p.outLimits.Set(key, cache.NewItem(lim, p.options.refreshInterval))

	return lim
}

func (p *cachedTrafficLimiter) equal(lim1, lim2 traffic.Limiter) bool {
	if lim1 == lim2 {
		return true
	}

	if lim1 == nil || lim2 == nil {
		return false
	}

	return lim1.Limit() == lim2.Limit()
}
