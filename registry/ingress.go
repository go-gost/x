package registry

import (
	"context"

	"github.com/go-gost/core/ingress"
)

type ingressRegistry struct {
	registry[ingress.Ingress]
}

func (r *ingressRegistry) Register(name string, v ingress.Ingress) error {
	return r.registry.Register(name, v)
}

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
