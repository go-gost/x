package registry

import (
	"context"
	"net"

	"github.com/go-gost/core/resolver"
)

// resolverRegistry implements a hot-reload-safe registry for resolver.Resolver.
type resolverRegistry struct {
	registry[resolver.Resolver]
}

// Register stores a Resolver under the given name.
func (r *resolverRegistry) Register(name string, v resolver.Resolver) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Resolver.
// Returns nil if name is empty.
func (r *resolverRegistry) Get(name string) resolver.Resolver {
	if name != "" {
		return &resolverWrapper{name: name, r: r}
	}
	return nil
}

func (r *resolverRegistry) get(name string) resolver.Resolver {
	return r.registry.Get(name)
}

type resolverWrapper struct {
	name string
	r    *resolverRegistry
}

func (w *resolverWrapper) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) ([]net.IP, error) {
	r := w.r.get(w.name)
	if r == nil {
		return nil, resolver.ErrInvalid
	}
	return r.Resolve(ctx, network, host, opts...)
}
