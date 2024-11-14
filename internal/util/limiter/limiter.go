package limiter

import (
	"context"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
)

type cachedTrafficLimiter struct {
	inLimits        *Cache
	outLimits       *Cache
	limiter         traffic.TrafficLimiter
	refreshInterval time.Duration
}

func NewCachedTrafficLimiter(limiter traffic.TrafficLimiter, refreshInterval time.Duration, cleanupInterval time.Duration) traffic.TrafficLimiter {
	if limiter == nil {
		return nil
	}

	lim := &cachedTrafficLimiter{
		inLimits:        NewCache(cleanupInterval),
		outLimits:       NewCache(cleanupInterval),
		limiter:         limiter,
		refreshInterval: refreshInterval,
	}
	return lim
}

func (p *cachedTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.limiter == nil {
		return nil
	}

	item := p.inLimits.Get(key)
	lim, _ := item.Value().(traffic.Limiter)
	if !item.Expired() {
		return lim
	}

	limNew := p.limiter.In(ctx, key, opts...)
	if limNew == nil {
		limNew = lim
	}
	if item == nil || !p.equal(lim, limNew) {
		p.inLimits.Set(key, NewItem(limNew, p.refreshInterval))
		return limNew
	}

	p.inLimits.Set(key, NewItem(lim, p.refreshInterval))

	return lim
}

func (p *cachedTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.limiter == nil {
		return nil
	}

	item := p.outLimits.Get(key)
	lim, _ := item.Value().(traffic.Limiter)
	if !item.Expired() {
		return lim
	}

	limNew := p.limiter.Out(ctx, key, opts...)
	if limNew == nil {
		limNew = lim
	}
	if item == nil || !p.equal(lim, limNew) {
		p.outLimits.Set(key, NewItem(limNew, p.refreshInterval))
		return limNew
	}

	p.outLimits.Set(key, NewItem(lim, p.refreshInterval))

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
