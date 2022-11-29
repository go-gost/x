package registry

import (
	"context"

	"github.com/go-gost/core/chain"
)

type hopRegistry struct {
	registry[chain.Hop]
}

func (r *hopRegistry) Register(name string, v chain.Hop) error {
	return r.registry.Register(name, v)
}

func (r *hopRegistry) Get(name string) chain.Hop {
	if name != "" {
		return &hopWrapper{name: name, r: r}
	}
	return nil
}

func (r *hopRegistry) get(name string) chain.Hop {
	return r.registry.Get(name)
}

type hopWrapper struct {
	name string
	r    *hopRegistry
}

func (w *hopWrapper) Nodes() []*chain.Node {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Nodes()
}

func (w *hopWrapper) Select(ctx context.Context, opts ...chain.SelectOption) *chain.Node {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}

	return v.Select(ctx, opts...)
}
