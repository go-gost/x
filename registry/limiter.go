package registry

import (
	"context"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
)

// trafficLimiterRegistry implements a hot-reload-safe registry for traffic.TrafficLimiter.
type trafficLimiterRegistry struct {
	registry[traffic.TrafficLimiter]
}

// Register stores a TrafficLimiter under the given name.
func (r *trafficLimiterRegistry) Register(name string, v traffic.TrafficLimiter) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered TrafficLimiter.
// Returns nil if name is empty.
func (r *trafficLimiterRegistry) Get(name string) traffic.TrafficLimiter {
	if name != "" {
		return &trafficLimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *trafficLimiterRegistry) get(name string) traffic.TrafficLimiter {
	return r.registry.Get(name)
}

type trafficLimiterWrapper struct {
	name string
	r    *trafficLimiterRegistry
}

func (w *trafficLimiterWrapper) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.In(ctx, key, opts...)
}

func (w *trafficLimiterWrapper) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Out(ctx, key, opts...)
}

// connLimiterRegistry implements a hot-reload-safe registry for conn.ConnLimiter.
type connLimiterRegistry struct {
	registry[conn.ConnLimiter]
}

// Register stores a ConnLimiter under the given name.
func (r *connLimiterRegistry) Register(name string, v conn.ConnLimiter) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered ConnLimiter.
// Returns nil if name is empty.
func (r *connLimiterRegistry) Get(name string) conn.ConnLimiter {
	if name != "" {
		return &connLimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *connLimiterRegistry) get(name string) conn.ConnLimiter {
	return r.registry.Get(name)
}

type connLimiterWrapper struct {
	name string
	r    *connLimiterRegistry
}

func (w *connLimiterWrapper) Limiter(key string) conn.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Limiter(key)
}

// rateLimiterRegistry implements a hot-reload-safe registry for rate.RateLimiter.
type rateLimiterRegistry struct {
	registry[rate.RateLimiter]
}

// Register stores a RateLimiter under the given name.
func (r *rateLimiterRegistry) Register(name string, v rate.RateLimiter) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered RateLimiter.
// Returns nil if name is empty.
func (r *rateLimiterRegistry) Get(name string) rate.RateLimiter {
	if name != "" {
		return &rateLimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *rateLimiterRegistry) get(name string) rate.RateLimiter {
	return r.registry.Get(name)
}

type rateLimiterWrapper struct {
	name string
	r    *rateLimiterRegistry
}

func (w *rateLimiterWrapper) Limiter(key string) rate.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Limiter(key)
}
