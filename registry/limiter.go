package registry

import (
	"github.com/go-gost/core/limiter"
)

type rlimiterRegistry struct {
	registry
}

func (r *rlimiterRegistry) Register(name string, v limiter.RateLimiter) error {
	return r.registry.Register(name, v)
}

func (r *rlimiterRegistry) Get(name string) limiter.RateLimiter {
	if name != "" {
		return &rlimiterWrapper{name: name, r: r}
	}
	return nil
}

func (r *rlimiterRegistry) get(name string) limiter.RateLimiter {
	if v := r.registry.Get(name); v != nil {
		return v.(limiter.RateLimiter)
	}
	return nil
}

type rlimiterWrapper struct {
	name string
	r    *rlimiterRegistry
}

func (w *rlimiterWrapper) Input() limiter.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Input()
}

func (w *rlimiterWrapper) Output() limiter.Limiter {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Output()
}
