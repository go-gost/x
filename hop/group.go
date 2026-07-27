package hop

import (
	"context"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/routing"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/x/internal/probe"
	xlogger "github.com/go-gost/x/logger"
	xs "github.com/go-gost/x/selector"
)

// HopEntry wraps a hop.Hop with an optional matcher and an independent
// failure marker for hop-level probe tracking. The entry's marker is
// separate from any node-level markers inside the hop so that probe
// Reset() cannot undo a node-level failCodes Mark().
type HopEntry struct {
	hop     hop.Hop
	matcher routing.Matcher
	probe   *chain.ProbeConfig
	marker  selector.Marker
}

// NewHopEntry creates a HopEntry. matcher may be nil (unconditional
// catch-all). probe may be nil (no health check for this entry).
func NewHopEntry(h hop.Hop, m routing.Matcher, probe *chain.ProbeConfig) *HopEntry {
	return &HopEntry{
		hop:     h,
		matcher: m,
		probe:   probe,
		marker:  selector.NewFailMarker(),
	}
}

func (e *HopEntry) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	return e.hop.Select(ctx, opts...)
}

// Marker implements selector.Markable.
func (e *HopEntry) Marker() selector.Marker {
	return e.marker
}

// HopGroupOption configures a hopGroup.
type HopGroupOption func(*hopGroupOptions)

type hopGroupOptions struct {
	entries  []*HopEntry
	selector selector.Selector[hop.Hop]
	logger   logger.Logger
}

// WithEntriesOption sets the hop entries for the group.
func WithEntriesOption(entries ...*HopEntry) HopGroupOption {
	return func(o *hopGroupOptions) {
		o.entries = entries
	}
}

// WithGroupSelectorOption sets the selector for the group.
func WithGroupSelectorOption(s selector.Selector[hop.Hop]) HopGroupOption {
	return func(o *hopGroupOptions) {
		o.selector = s
	}
}

// WithGroupLoggerOption sets the logger for the group.
func WithGroupLoggerOption(log logger.Logger) HopGroupOption {
	return func(o *hopGroupOptions) {
		o.logger = log
	}
}

type hopGroup struct {
	entries    []*HopEntry
	selector   selector.Selector[hop.Hop]
	logger     logger.Logger
	cancelFunc context.CancelFunc
}

// NewHopGroup creates a new hopGroup and starts probe goroutines for
// entries that have probe configurations.
func NewHopGroup(opts ...HopGroupOption) *hopGroup {
	var options hopGroupOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &hopGroup{
		entries:    options.entries,
		selector:   options.selector,
		logger:     options.logger,
		cancelFunc: cancel,
	}

	if g.logger == nil {
		g.logger = xlogger.Nop()
	}
	if g.selector == nil {
		g.selector = xs.NewSelector(
			xs.RoundRobinStrategy[hop.Hop](),
			xs.FailFilter[hop.Hop](xs.DefaultMaxFails, xs.DefaultFailTimeout),
			xs.BackupFilter[hop.Hop](),
		)
	}

	for _, e := range g.entries {
		if e.probe != nil {
			go g.runEntryProbe(ctx, e)
		}
	}

	return g
}

// Select implements hop.Hop. It filters entries by matcher, applies the
// group selector pipeline (FailFilter + strategy) to pick one hop entry,
// and delegates to the chosen entry's underlying hop.
func (g *hopGroup) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if g == nil || len(g.entries) == 0 {
		return nil
	}

	var options hop.SelectOptions
	for _, opt := range opts {
		opt(&options)
	}

	// Stage 1: matcher filter — build eligible pool.
	req := routing.Request{
		Network:  options.Network,
		Host:     options.Host,
		Protocol: options.Protocol,
		Method:   options.Method,
		Path:     options.Path,
		Query:    options.Query,
		Header:   options.Header,
		Body:     options.Body,
		ClientIP: options.ClientIP,
	}

	var eligible []hop.Hop
	for _, e := range g.entries {
		if e.matcher != nil {
			if !e.matcher.Match(&req) {
				continue
			}
			g.logger.Debugf("hop entry matched request %s %s", req.Protocol, req.Host)
		}
		eligible = append(eligible, e)
	}

	if len(eligible) == 0 {
		return nil
	}
	if len(eligible) == 1 {
		return eligible[0].Select(ctx, opts...)
	}

	// Stage 2: group selector — FailFilter + strategy.
	if g.selector != nil {
		if se := g.selector.Select(ctx, eligible...); se != nil {
			return se.Select(ctx, opts...)
		}
	}
	return eligible[0].Select(ctx, opts...)
}

// Nodes implements hop.NodeList, aggregating all nodes from every entry.
func (g *hopGroup) Nodes() []*chain.Node {
	if g == nil {
		return nil
	}
	var nodes []*chain.Node
	for _, e := range g.entries {
		if nl, ok := e.hop.(hop.NodeList); ok {
			nodes = append(nodes, nl.Nodes()...)
		}
	}
	return nodes
}

// Close stops all probe goroutines and closes each hop entry.
func (g *hopGroup) Close() error {
	g.cancelFunc()
	for _, e := range g.entries {
		if closer, ok := e.hop.(interface{ Close() error }); ok {
			closer.Close()
		}
	}
	return nil
}

// runEntryProbe periodically probes a node sampled from the hop and marks
// the hop entry (not the node) on failure. This keeps the entry's marker
// independent of node-level markers — probe Reset() cannot undo a
// failCodes Mark().
func (g *hopGroup) runEntryProbe(ctx context.Context, e *HopEntry) {
	cfg := e.probe
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	g.probeEntry(e, cfg) // first probe immediately
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.probeEntry(e, cfg)
		case <-ctx.Done():
			return
		}
	}
}

func (g *hopGroup) probeEntry(e *HopEntry, cfg *chain.ProbeConfig) {
	// cmd probe runs a shell command — no node selection needed.
	if cfg.Type == chain.ProbeTypeCmd {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		err := (&probe.CmdProber{Command: cfg.Command, Timeout: timeout}).Probe()
		if err != nil {
			e.marker.Mark()
			g.logger.Debugf("hop entry cmd probe failed: %v", err)
		} else {
			e.marker.Reset()
		}
		return
	}

	// Select a node from the hop — round-robin sampling over time.
	node := e.hop.Select(context.Background())
	if node == nil {
		e.marker.Mark()
		g.logger.Debug("hop entry probe: no node available")
		return
	}

	// Probe through the node's transport (same pattern as
	// x/chain/node.go probeNode).
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tr := node.Options().Transport
	conn, err := tr.Dial(probeCtx, node.Addr)
	if err != nil {
		e.marker.Mark()
		g.logger.Debugf("hop entry probe dial %s failed: %v", node.Addr, err)
		return
	}

	if hc, err2 := tr.Handshake(probeCtx, conn); err2 == nil {
		conn = hc
	} else {
		conn.Close()
		e.marker.Mark()
		g.logger.Debugf("hop entry probe handshake %s failed: %v", node.Addr, err2)
		return
	}

	if cfg.Type == chain.ProbeTypeHTTP {
		err = probe.NewHTTPProber(cfg).Probe(conn)
		conn.Close()
		if err != nil {
			e.marker.Mark()
			g.logger.Debugf("hop entry probe http %s failed: %v", node.Addr, err)
			return
		}
	} else {
		conn.Close()
	}

	e.marker.Reset()
}
