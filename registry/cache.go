package registry

import (
	"context"

	"github.com/go-gost/core/cache"
)

// cacheRegistry implements a hot-reload-safe registry for cache.Cache.
type cacheRegistry struct {
	registry[cache.Cache]
}

// Register stores a Cache under the given name.
func (r *cacheRegistry) Register(name string, v cache.Cache) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Cache.
// Returns nil if name is empty.
func (r *cacheRegistry) Get(name string) cache.Cache {
	if name != "" {
		return &cacheWrapper{name: name, r: r}
	}
	return nil
}

func (r *cacheRegistry) get(name string) cache.Cache {
	return r.registry.Get(name)
}

type cacheWrapper struct {
	name string
	r    *cacheRegistry
}

func (w *cacheWrapper) Get(ctx context.Context, key string) (*cache.Entry, error) {
	v := w.r.get(w.name)
	if v == nil {
		return nil, cache.ErrNotFound
	}
	return v.Get(ctx, key)
}

func (w *cacheWrapper) Set(ctx context.Context, key string, data []byte, opts ...cache.SetOption) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Set(ctx, key, data, opts...)
}

func (w *cacheWrapper) Delete(ctx context.Context, key string) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Delete(ctx, key)
}
