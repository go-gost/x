package registry

import (
	"context"

	"github.com/go-gost/core/admission"
)

type admissionRegistry struct {
	registry[admission.Admission]
}

func (r *admissionRegistry) Register(name string, v admission.Admission) error {
	return r.registry.Register(name, v)
}

func (r *admissionRegistry) Get(name string) admission.Admission {
	if name != "" {
		return &admissionWrapper{name: name, r: r}
	}
	return nil
}

func (r *admissionRegistry) get(name string) admission.Admission {
	return r.registry.Get(name)
}

type admissionWrapper struct {
	name string
	r    *admissionRegistry
}

func (w *admissionWrapper) Admit(ctx context.Context, addr string, opts ...admission.Option) bool {
	p := w.r.get(w.name)
	if p == nil {
		return false
	}
	return p.Admit(ctx, addr, opts...)
}
