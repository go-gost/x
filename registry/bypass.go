package registry

import (
	"context"

	"github.com/go-gost/core/bypass"
)

type bypassRegistry struct {
	registry[bypass.Bypass]
}

func (r *bypassRegistry) Register(name string, v bypass.Bypass) error {
	return r.registry.Register(name, v)
}

func (r *bypassRegistry) Get(name string) bypass.Bypass {
	if name != "" {
		return &bypassWrapper{name: name, r: r}
	}
	return nil
}

func (r *bypassRegistry) get(name string) bypass.Bypass {
	return r.registry.Get(name)
}

type bypassWrapper struct {
	name string
	r    *bypassRegistry
}

func (w *bypassWrapper) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	bp := w.r.get(w.name)
	if bp == nil {
		return false
	}
	return bp.Contains(ctx, network, addr, opts...)
}

func (p *bypassWrapper) IsWhitelist() bool {
	bp := p.r.get(p.name)
	if bp == nil {
		return false
	}
	return bp.IsWhitelist()
}
