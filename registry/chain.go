package registry

import (
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/selector"
)

type chainRegistry struct {
	registry
}

func (r *chainRegistry) Register(name string, v chain.SelectableChainer) error {
	return r.registry.Register(name, v)
}

func (r *chainRegistry) Get(name string) chain.SelectableChainer {
	if name != "" {
		return &chainWrapper{name: name, r: r}
	}
	return nil
}

func (r *chainRegistry) get(name string) chain.SelectableChainer {
	if v := r.registry.Get(name); v != nil {
		return v.(chain.SelectableChainer)
	}
	return nil
}

type chainWrapper struct {
	name string
	r    *chainRegistry
}

func (w *chainWrapper) Marker() selector.Marker {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Marker()
}

func (w *chainWrapper) Metadata() metadata.Metadata {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Metadata()
}

func (w *chainWrapper) Route(network, address string) chain.Route {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Route(network, address)
}
