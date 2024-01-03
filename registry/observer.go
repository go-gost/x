package registry

import (
	"context"

	"github.com/go-gost/core/observer"
)

type observerRegistry struct {
	registry[observer.Observer]
}

func (r *observerRegistry) Register(name string, v observer.Observer) error {
	return r.registry.Register(name, v)
}

func (r *observerRegistry) Get(name string) observer.Observer {
	if name != "" {
		return &observerWrapper{name: name, r: r}
	}
	return nil
}

func (r *observerRegistry) get(name string) observer.Observer {
	return r.registry.Get(name)
}

type observerWrapper struct {
	name string
	r    *observerRegistry
}

func (w *observerWrapper) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Observe(ctx, events, opts...)
}
