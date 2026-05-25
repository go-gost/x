package registry

import (
	"context"

	"github.com/go-gost/core/admission"
)

// admissionRegistry implements a hot-reload-safe registry for admission.Admission.
// The Get method returns a wrapper that looks up the current value on every call.
type admissionRegistry struct {
	registry[admission.Admission]
}

// Register stores an Admission under the given name.
func (r *admissionRegistry) Register(name string, v admission.Admission) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Admission.
// Returns nil if name is empty.
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

func (w *admissionWrapper) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	p := w.r.get(w.name)
	if p == nil {
		return false
	}
	return p.Admit(ctx, network, addr, opts...)
}
