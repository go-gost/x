package registry

import (
	"context"
	"net"

	"github.com/go-gost/core/hosts"
)

type hostsRegistry struct {
	registry[hosts.HostMapper]
}

func (r *hostsRegistry) Register(name string, v hosts.HostMapper) error {
	return r.registry.Register(name, v)
}

func (r *hostsRegistry) Get(name string) hosts.HostMapper {
	if name != "" {
		return &hostsWrapper{name: name, r: r}
	}
	return nil
}

func (r *hostsRegistry) get(name string) hosts.HostMapper {
	return r.registry.Get(name)
}

type hostsWrapper struct {
	name string
	r    *hostsRegistry
}

func (w *hostsWrapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	v := w.r.get(w.name)
	if v == nil {
		return nil, false
	}
	return v.Lookup(ctx, network, host, opts...)
}
