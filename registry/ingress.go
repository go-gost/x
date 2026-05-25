package registry

import (
	"context"

	"github.com/go-gost/core/ingress"
)

// ingressRegistry implements a hot-reload-safe registry for ingress.Ingress.
type ingressRegistry struct {
	registry[ingress.Ingress]
}

// Register stores an Ingress under the given name.
func (r *ingressRegistry) Register(name string, v ingress.Ingress) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Ingress.
// Returns nil if name is empty.
func (r *ingressRegistry) Get(name string) ingress.Ingress {
	if name != "" {
		return &ingressWrapper{name: name, r: r}
	}
	return nil
}

func (r *ingressRegistry) get(name string) ingress.Ingress {
	return r.registry.Get(name)
}

type ingressWrapper struct {
	name string
	r    *ingressRegistry
}

func (w *ingressWrapper) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.GetRule(ctx, host, opts...)
}

func (w *ingressWrapper) SetRule(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool {
	v := w.r.get(w.name)
	if v == nil {
		return false
	}

	return v.SetRule(ctx, rule, opts...)
}
