package registry

import (
	"context"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
)

// hopRegistry implements a hot-reload-safe registry for hop.Hop.
type hopRegistry struct {
	registry[hop.Hop]
}

// Register stores a Hop under the given name.
func (r *hopRegistry) Register(name string, v hop.Hop) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Hop.
// Returns nil if name is empty.
func (r *hopRegistry) Get(name string) hop.Hop {
	if name != "" {
		return &hopWrapper{name: name, r: r}
	}
	return nil
}

func (r *hopRegistry) get(name string) hop.Hop {
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
	if nl, ok := v.(hop.NodeList); ok {
		return nl.Nodes()
	}
	return nil
}

func (w *hopWrapper) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}

	return v.Select(ctx, opts...)
}
