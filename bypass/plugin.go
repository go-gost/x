package bypass

import (
	"context"

	bypass_pkg "github.com/go-gost/core/bypass"
	"github.com/go-gost/plugin/bypass/proto"
	xlogger "github.com/go-gost/x/logger"
)

type pluginBypass struct {
	client  proto.BypassClient
	options options
}

// NewPluginBypass creates a plugin bypass.
func NewPluginBypass(opts ...Option) bypass_pkg.Bypass {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	if options.logger == nil {
		options.logger = xlogger.Nop()
	}

	p := &pluginBypass{
		options: options,
	}
	if options.client != nil {
		p.client = proto.NewBypassClient(options.client)
	}
	return p
}

func (p *pluginBypass) Contains(ctx context.Context, addr string) bool {
	if p.client == nil {
		return false
	}

	r, err := p.client.Bypass(ctx,
		&proto.BypassRequest{
			Addr: addr,
		})
	if err != nil {
		p.options.logger.Error(err)
		return false
	}
	return r.Ok
}

func (p *pluginBypass) Close() error {
	if p.options.client != nil {
		return p.options.client.Close()
	}
	return nil
}
