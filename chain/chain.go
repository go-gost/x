// Package chain implements the core routing infrastructure for GOST.
//
// It provides three key abstractions:
//
//   - Router: top-level entry point that resolves addresses, selects routes
//     via a Chainer, retries on failure, and records telemetry.
//
//   - Chain: a named sequence of proxy hops (nodes). Each hop selects a node
//     from its group, and the resulting Route carries traffic through every
//     selected node in order.
//
//   - Transport: bundles a dialer and connector for a single chain node. It
//     handles Dial, Handshake, Connect, and Bind — the four steps needed to
//     move traffic through a proxy hop.
//
// # Route traversal
//
// For a chain of N nodes, the first node is reached via Dial → Handshake,
// and each subsequent node via Connect → Handshake through the previous
// connection. On failure, connections are cleaned up and nodes are marked
// so selectors can deprioritize them.
//
// # Multiplexing
//
// When a node's transport supports multiplexing, Chain splits the route at
// that point: nodes before the multiplex-capable node form a sub-route that is
// copied into the transport, establishing a reusable tunnel for subsequent
// connections.
package chain

import (
	"context"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/selector"
)

var (
	_ chain.Chainer = (*chainGroup)(nil)
)

type ChainOptions struct {
	Metadata metadata.Metadata
	Logger   logger.Logger
}

type ChainOption func(*ChainOptions)

func MetadataChainOption(md metadata.Metadata) ChainOption {
	return func(opts *ChainOptions) {
		opts.Metadata = md
	}
}

func LoggerChainOption(logger logger.Logger) ChainOption {
	return func(opts *ChainOptions) {
		opts.Logger = logger
	}
}

type chainNamer interface {
	Name() string
}

type Chain struct {
	name     string
	hops     []hop.Hop
	marker   selector.Marker
	metadata metadata.Metadata
	logger   logger.Logger
}

// NewChain creates a new Chain with the given name and options.
func NewChain(name string, opts ...ChainOption) *Chain {
	var options ChainOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	return &Chain{
		name:     name,
		metadata: options.Metadata,
		marker:   selector.NewFailMarker(),
		logger:   options.Logger,
	}
}

// AddHop appends a hop to the chain. Hops are traversed in order during
// route construction.
func (c *Chain) AddHop(hop hop.Hop) {
	c.hops = append(c.hops, hop)
}

// Metadata returns the chain's metadata.
// Implements metadata.Metadatable interface.
func (c *Chain) Metadata() metadata.Metadata {
	return c.metadata
}

// Marker implements selector.Markable interface.
func (c *Chain) Marker() selector.Marker {
	return c.marker
}

func (c *Chain) Name() string {
	return c.name
}

// Route builds a route by selecting one node from each hop. If a node
// supports multiplexing, the route is split — nodes before it form a
// sub-route that is copied into the transport for reuse.
func (c *Chain) Route(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Route {
	if c == nil || len(c.hops) == 0 {
		return nil
	}

	var options chain.RouteOptions
	for _, opt := range opts {
		opt(&options)
	}

	rt := NewRoute(ChainRouteOption(c))
	for _, h := range c.hops {
		node := h.Select(ctx,
			hop.NetworkSelectOption(network),
			hop.AddrSelectOption(address),
			hop.HostSelectOption(options.Host),
		)
		if node == nil {
			return rt
		}
		if node.Options().Transport.Multiplex() {
			tr := node.Options().Transport.Copy()
			tr.Options().Route = rt
			node = node.Copy()
			node.Options().Transport = tr
			rt = NewRoute(ChainRouteOption(c))
		}

		rt.addNode(node)
	}
	return rt
}

type chainGroup struct {
	chains   []chain.Chainer
	selector selector.Selector[chain.Chainer]
}

// NewChainGroup creates a chain group that selects one Chainer from the
// given list using the configured selector (round-robin by default).
func NewChainGroup(chains ...chain.Chainer) *chainGroup {
	return &chainGroup{chains: chains}
}

func (p *chainGroup) WithSelector(s selector.Selector[chain.Chainer]) *chainGroup {
	p.selector = s
	return p
}

func (p *chainGroup) Route(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Route {
	if chain := p.next(ctx); chain != nil {
		return chain.Route(ctx, network, address, opts...)
	}
	return nil
}

func (p *chainGroup) next(ctx context.Context) chain.Chainer {
	if p == nil || len(p.chains) == 0 {
		return nil
	}

	return p.selector.Select(ctx, p.chains...)
}
