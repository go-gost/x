package registry

import (
	"context"
	"io"

	"github.com/go-gost/core/observer"
)

// observerRegistry implements a hot-reload-safe registry for observer.Observer.
type observerRegistry struct {
	registry[observer.Observer]
}

// Register stores an Observer under the given name.
func (r *observerRegistry) Register(name string, v observer.Observer) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Observer.
// Returns nil if name is empty.
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

// Close closes the underlying observer if it implements io.Closer.
func (w *observerWrapper) Close() error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	if closer, ok := v.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
