package registry

import (
	"context"

	"github.com/go-gost/core/rewriter"
)

// rewriterRegistry implements a hot-reload-safe registry for rewriter.Rewriter.
type rewriterRegistry struct {
	registry[rewriter.Rewriter]
}

// Register stores a Rewriter under the given name.
func (r *rewriterRegistry) Register(name string, v rewriter.Rewriter) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Rewriter.
// Returns nil if name is empty.
func (r *rewriterRegistry) Get(name string) rewriter.Rewriter {
	if name != "" {
		return &rewriterWrapper{name: name, r: r}
	}
	return nil
}

func (r *rewriterRegistry) get(name string) rewriter.Rewriter {
	return r.registry.Get(name)
}

type rewriterWrapper struct {
	name string
	r    *rewriterRegistry
}

func (w *rewriterWrapper) Rewrite(ctx context.Context, b []byte, opts ...rewriter.RewriteOption) ([]byte, error) {
	v := w.r.get(w.name)
	if v == nil {
		return b, nil
	}
	return v.Rewrite(ctx, b, opts...)
}
