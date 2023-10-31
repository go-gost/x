package registry

import (
	"context"

	"github.com/go-gost/core/sd"
)

type sdRegistry struct {
	registry[sd.SD]
}

func (r *sdRegistry) Register(name string, v sd.SD) error {
	return r.registry.Register(name, v)
}

func (r *sdRegistry) Get(name string) sd.SD {
	if name != "" {
		return &sdWrapper{name: name, r: r}
	}
	return nil
}

func (r *sdRegistry) get(name string) sd.SD {
	return r.registry.Get(name)
}

type sdWrapper struct {
	name string
	r    *sdRegistry
}

func (w *sdWrapper) Register(ctx context.Context, name string, network, address string, opts ...sd.Option) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Register(ctx, name, network, address, opts...)
}

func (w *sdWrapper) Deregister(ctx context.Context, name string) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}

	return v.Deregister(ctx, name)
}

func (w *sdWrapper) Renew(ctx context.Context, name string) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}

	return v.Renew(ctx, name)
}

func (w *sdWrapper) Get(ctx context.Context, name string) ([]*sd.Service, error) {
	v := w.r.get(w.name)
	if v == nil {
		return nil, nil
	}

	return v.Get(ctx, name)
}
