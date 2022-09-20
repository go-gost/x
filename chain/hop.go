package chain

import (
	"context"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/selector"
)

type HopOptions struct {
	bypass   bypass.Bypass
	selector selector.Selector[*chain.Node]
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

	return &chainHop{
		nodes:   nodes,
		options: options,
	}
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
	if p.options.bypass != nil && p.options.bypass.Contains(options.Addr) {
		return nil
	}

	var nodes []*chain.Node
	for _, node := range p.nodes {
		if node == nil {
			continue
		}
		// node level bypass
		if node.Options().Bypass != nil && node.Options().Bypass.Contains(options.Addr) {
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
