package registry

import (
	"context"

	"github.com/go-gost/core/router"
)

type routerRegistry struct {
	registry[router.Router]
}

func (r *routerRegistry) Register(name string, v router.Router) error {
	return r.registry.Register(name, v)
}

func (r *routerRegistry) Get(name string) router.Router {
	if name != "" {
		return &routerWrapper{name: name, r: r}
	}
	return nil
}

func (r *routerRegistry) get(name string) router.Router {
	return r.registry.Get(name)
}

type routerWrapper struct {
	name string
	r    *routerRegistry
}

func (w *routerWrapper) GetRoute(ctx context.Context, dst string, opts ...router.Option) *router.Route {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.GetRoute(ctx, dst, opts...)
}
