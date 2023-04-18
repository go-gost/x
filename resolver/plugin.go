package resolver

import (
	"context"
	"net"

	resolver_pkg "github.com/go-gost/core/resolver"
	"github.com/go-gost/plugin/resolver/proto"
	xlogger "github.com/go-gost/x/logger"
)

type pluginResolver struct {
	client  proto.ResolverClient
	options options
}

// NewPluginResolver creates a plugin Resolver.
func NewPluginResolver(opts ...Option) (resolver_pkg.Resolver, error) {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	if options.logger == nil {
		options.logger = xlogger.Nop()
	}

	p := &pluginResolver{
		options: options,
	}
	if options.client != nil {
		p.client = proto.NewResolverClient(options.client)
	}
	return p, nil
}

func (p *pluginResolver) Resolve(ctx context.Context, network, host string) (ips []net.IP, err error) {
	p.options.logger.Debugf("resolve %s/%s", host, network)

	if p.client == nil {
		return
	}

	r, err := p.client.Resolve(context.Background(),
		&proto.ResolveRequest{
			Network: network,
			Host:    host,
		})
	if err != nil {
		p.options.logger.Error(err)
		return
	}
	for _, s := range r.Ips {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return
}

func (p *pluginResolver) Close() error {
	if p.options.client != nil {
		return p.options.client.Close()
	}
	return nil
}
