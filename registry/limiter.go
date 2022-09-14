package registry

import (
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
)

type trafficLimiterRegistry struct {
	registry
}

func (r *trafficLimiterRegistry) Register(name string, v traffic.TrafficLimiter) error {
	return r.registry.Register(name, v)
}

func (r *trafficLimiterRegistry) Get(name string) traffic.TrafficLimiter {
	if name != "" {
		return &trafficLimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *trafficLimiterRegistry) get(name string) traffic.TrafficLimiter {
	if v := r.registry.Get(name); v != nil {
		return v.(traffic.TrafficLimiter)
	}
	return nil
}

type trafficLimiterWrapper struct {
	name string
	r    *trafficLimiterRegistry
}

func (w *trafficLimiterWrapper) In(key string) traffic.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.In(key)
}

func (w *trafficLimiterWrapper) Out(key string) traffic.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Out(key)
}

type connLimiterRegistry struct {
	registry
}

func (r *connLimiterRegistry) Register(name string, v conn.ConnLimiter) error {
	return r.registry.Register(name, v)
}

func (r *connLimiterRegistry) Get(name string) conn.ConnLimiter {
	if name != "" {
		return &connLimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *connLimiterRegistry) get(name string) conn.ConnLimiter {
	if v := r.registry.Get(name); v != nil {
		return v.(conn.ConnLimiter)
	}
	return nil
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

type rateLimiterRegistry struct {
	registry
}

func (r *rateLimiterRegistry) Register(name string, v rate.RateLimiter) error {
	return r.registry.Register(name, v)
}

func (r *rateLimiterRegistry) Get(name string) rate.RateLimiter {
	if name != "" {
		return &rateLimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *rateLimiterRegistry) get(name string) rate.RateLimiter {
	if v := r.registry.Get(name); v != nil {
		return v.(rate.RateLimiter)
	}
	return nil
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
