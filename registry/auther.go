package registry

import (
	"context"

	"github.com/go-gost/core/auth"
)

// autherRegistry implements a hot-reload-safe registry for auth.Authenticator.
type autherRegistry struct {
	registry[auth.Authenticator]
}

// Register stores an Authenticator under the given name.
func (r *autherRegistry) Register(name string, v auth.Authenticator) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Authenticator.
// Returns nil if name is empty.
func (r *autherRegistry) Get(name string) auth.Authenticator {
	if name != "" {
		return &autherWrapper{name: name, r: r}
	}
	return nil
}

func (r *autherRegistry) get(name string) auth.Authenticator {
	return r.registry.Get(name)
}

type autherWrapper struct {
	name string
	r    *autherRegistry
}

func (w *autherWrapper) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	v := w.r.get(w.name)
	if v == nil {
		return "", true
	}
	return v.Authenticate(ctx, user, password, opts...)
}
