package chain

import (
	"context"
	"net"
	"strings"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/selector"
)

type HopOptions struct {
	bypass   bypass.Bypass
	selector selector.Selector[*chain.Node]
	logger   logger.Logger
}

type HopOption func(*HopOptions)

func BypassHopOption(bp bypass.Bypass) HopOption {
	return func(o *HopOptions) {
		o.bypass = bp
	}
}

func SelectorHopOption(s selector.Selector[*chain.Node]) HopOption {
	return func(o *HopOptions) {
		o.selector = s
	}
}

func LoggerHopOption(logger logger.Logger) HopOption {
	return func(opts *HopOptions) {
		opts.logger = logger
	}
}

type chainHop struct {
	nodes   []*chain.Node
	options HopOptions
}

func NewChainHop(nodes []*chain.Node, opts ...HopOption) chain.Hop {
	var options HopOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	hop := &chainHop{
		nodes:   nodes,
		options: options,
	}

	return hop
}

func (p *chainHop) Nodes() []*chain.Node {
	return p.nodes
}

func (p *chainHop) Select(ctx context.Context, opts ...chain.SelectOption) *chain.Node {
	var options chain.SelectOptions
	for _, opt := range opts {
		opt(&options)
	}

	if p == nil || len(p.nodes) == 0 {
		return nil
	}

	// hop level bypass
	if p.options.bypass != nil &&
		p.options.bypass.Contains(options.Addr) {
		return nil
	}

	filters := p.nodes
	if host := options.Host; host != "" {
		filters = nil
		if v, _, _ := net.SplitHostPort(host); v != "" {
			host = v
		}
		var nodes []*chain.Node
		for _, node := range p.nodes {
			if node == nil {
				continue
			}
			vhost := node.Options().Host
			if vhost == "" {
				nodes = append(nodes, node)
				continue
			}
			if vhost == host ||
				vhost[0] == '.' && strings.HasSuffix(host, vhost[1:]) {
				filters = append(filters, node)
				p.options.logger.Debugf("find node for host: %s(match %s)", host, vhost)
			}
		}
		if len(filters) == 0 {
			filters = nodes
		}
	}

	var nodes []*chain.Node
	for _, node := range filters {
		if node == nil {
			continue
		}
		// node level bypass
		if node.Options().Bypass != nil &&
			node.Options().Bypass.Contains(options.Addr) {
			continue
		}

		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil
	}

	if s := p.options.selector; s != nil {
		return s.Select(ctx, nodes...)
	}
	return nodes[0]
}
