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
	"io"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/routing"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/x/internal/probe"
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

// Close stops all probe goroutines by cascading to each hop's Close,
// which in turn cascades to node.Close() for every node.
func (c *Chain) Close() error {
	for _, h := range c.hops {
		if closer, ok := h.(io.Closer); ok {
			closer.Close()
		}
	}
	return nil
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
	entries    []*ChainEntry
	selector   selector.Selector[chain.Chainer]
	logger     logger.Logger
	cancelFunc context.CancelFunc
}

// NewChainGroup creates a chain group that selects one Chainer from the
// given list using the configured selector (round-robin by default).
func NewChainGroup(chains ...chain.Chainer) *chainGroup {
	entries := make([]*ChainEntry, len(chains))
	for i, c := range chains {
		entries[i] = NewChainEntry(c, nil, nil)
	}
	return &chainGroup{entries: entries}
}

func (p *chainGroup) WithSelector(s selector.Selector[chain.Chainer]) *chainGroup {
	p.selector = s
	return p
}

// WithGroupEntries sets the chain entries for the group (replaces defaults)
// and starts probe goroutines for entries that have probe configurations.
func (p *chainGroup) WithGroupEntries(entries ...*ChainEntry) *chainGroup {
	// Cancel any previous probe goroutines before replacing entries.
	if p.cancelFunc != nil {
		p.cancelFunc()
	}
	p.entries = entries

	ctx, cancel := context.WithCancel(context.Background())
	p.cancelFunc = cancel
	for _, e := range entries {
		if e.probe != nil {
			go p.runEntryProbe(ctx, e)
		}
	}
	return p
}

// WithGroupLogger sets the logger for the group.
func (p *chainGroup) WithGroupLogger(log logger.Logger) *chainGroup {
	p.logger = log
	return p
}

func (p *chainGroup) Route(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Route {
	if c := p.selectChain(ctx, network, address, opts...); c != nil {
		return c.Route(ctx, network, address, opts...)
	}
	return nil
}

func (p *chainGroup) selectChain(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Chainer {
	if p == nil || len(p.entries) == 0 {
		return nil
	}

	var options chain.RouteOptions
	for _, opt := range opts {
		opt(&options)
	}

	// When no entry has a matcher, the eligible pool equals all entries; the
	// selector must still run (FailFilter excludes probe-failed chains), so
	// skip the per-call allocation and pass entries directly.
	anyMatcher := false
	for _, e := range p.entries {
		if e.matcher != nil {
			anyMatcher = true
			break
		}
	}
	if !anyMatcher {
		eligible := make([]chain.Chainer, len(p.entries))
		for i, e := range p.entries {
			eligible[i] = e
		}
		return p.selectFrom(ctx, eligible...)
	}

	// Stage 1: matcher filter — build eligible pool.
	req := routing.Request{
		Network: network,
		Host:    options.Host,
	}

	eligible := make([]chain.Chainer, 0, len(p.entries))
	for _, e := range p.entries {
		if e.matcher != nil {
			if !e.matcher.Match(&req) {
				continue
			}
			if p.logger != nil {
				p.logger.Debugf("chain entry matched request %s %s", req.Network, req.Host)
			}
		}
		eligible = append(eligible, e) // *ChainEntry as chain.Chainer, FailFilter reads e.Marker()
	}

	if len(eligible) == 0 {
		return nil
	}

	// Stage 2: group selector — FailFilter + strategy.
	return p.selectFrom(ctx, eligible...)
}

func (p *chainGroup) selectFrom(ctx context.Context, eligible ...chain.Chainer) chain.Chainer {
	if p.selector != nil {
		return p.selector.Select(ctx, eligible...)
	}
	return eligible[0]
}

// Close stops all probe goroutines.
func (p *chainGroup) Close() error {
	if p.cancelFunc != nil {
		p.cancelFunc()
	}
	return nil
}

// runEntryProbe periodically probes a chain and marks
// the chain entry (not the chain's nodes) on failure.
func (p *chainGroup) runEntryProbe(ctx context.Context, e *ChainEntry) {
	cfg := e.probe
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	p.probeEntry(ctx, e, cfg) // first probe immediately
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.probeEntry(ctx, e, cfg)
		case <-ctx.Done():
			return
		}
	}
}

func (p *chainGroup) probeEntry(ctx context.Context, e *ChainEntry, cfg *chain.ProbeConfig) {
	// cmd probe runs a shell command — no chain routing needed.
	if cfg.Type == chain.ProbeTypeCmd {
		probe.RunCmdProbe(cfg, e.marker, p.logger)
		return
	}

	// TCP/HTTP probe: route through the chain to probe target.
	addr := cfg.Addr
	if addr == "" {
		e.marker.Mark()
		if p.logger != nil {
			p.logger.Debug("chain entry probe: no probe address configured")
		}
		return
	}

	// Route through the probe lifecycle context so cancellation (reload/close)
	// aborts an in-flight probe instead of blocking forever on a stuck route.
	route := e.chainer.Route(ctx, "tcp", addr)
	if route == nil {
		e.marker.Mark()
		if p.logger != nil {
			p.logger.Debug("chain entry probe: no route available")
		}
		return
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := route.Dial(probeCtx, "tcp", addr)
	if err != nil {
		e.marker.Mark()
		if p.logger != nil {
			p.logger.Debugf("chain entry probe dial %s failed: %v", addr, err)
		}
		return
	}
	defer conn.Close()

	if cfg.Type == chain.ProbeTypeHTTP {
		if err := probe.NewHTTPProber(cfg).Probe(conn); err != nil {
			e.marker.Mark()
			if p.logger != nil {
				p.logger.Debugf("chain entry probe http %s failed: %v", addr, err)
			}
			return
		}
	}

	e.marker.Reset()
}
