// Package hop provides a hop (node group) implementation that selects a node
// from a group of proxy nodes using load-balancing strategies, filters, and
// bypass rules. It supports periodic reloading of node lists from file, Redis,
// or HTTP sources.
package hop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/routing"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/x/config"
	node_parser "github.com/go-gost/x/config/parsing/node"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
)

type options struct {
	name        string
	nodes       []*chain.Node
	bypass      bypass.Bypass
	selector    selector.Selector[*chain.Node]
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	logger      logger.Logger
}

// Option configures a hop.
type Option func(*options)

// NameOption sets the hop name.
func NameOption(name string) Option {
	return func(o *options) {
		o.name = name
	}
}

// NodeOption sets the initial node list for the hop.
func NodeOption(nodes ...*chain.Node) Option {
	return func(o *options) {
		o.nodes = nodes
	}
}

// BypassOption sets a hop-level bypass that can skip the entire hop.
func BypassOption(bp bypass.Bypass) Option {
	return func(o *options) {
		o.bypass = bp
	}
}

// SelectorOption sets the load-balancing strategy for node selection.
func SelectorOption(s selector.Selector[*chain.Node]) Option {
	return func(o *options) {
		o.selector = s
	}
}

// ReloadPeriodOption sets the interval for periodic reloading of node lists.
func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

// FileLoaderOption sets a loader that reads node configs from a file source.
func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

// RedisLoaderOption sets a loader that reads node configs from a Redis source.
func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

// HTTPLoaderOption sets a loader that reads node configs from an HTTP source.
func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}

// LoggerOption sets the logger for the hop.
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type chainHop struct {
	nodes      []*chain.Node
	options    options
	logger     logger.Logger
	mu         sync.RWMutex
	cancelFunc context.CancelFunc
}

// NewHop creates a new hop with the given options and starts periodic reloading.
func NewHop(opts ...Option) hop.Hop {
	var options options
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	ctx, cancel := context.WithCancel(context.TODO())
	p := &chainHop{
		nodes:      options.nodes,
		cancelFunc: cancel,
		options:    options,
		logger:     options.logger,
	}

	if p.logger == nil {
		p.logger = xlogger.Nop()
	}

	go p.periodReload(ctx)

	return p
}

func (p *chainHop) Nodes() []*chain.Node {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.nodes
}

// Select chooses a node from the hop group for the given request context.
//
// Selection pipeline:
//
//  1. Hop-level bypass         — entire hop skipped if bypass matches (addr/host)
//  2. Per-node filter (pool)   — each candidate must pass at least one gate:
//       a. routing.Matcher     — boolean expression (Host/Protocol/Method/Path/
//                                  Query/Header/Body). Match → non-zero Priority.
//       b. isEligible fallback — when no Matcher set, checks node Options.Filter:
//                                  checkHost(Host), checkProtocol(Protocol),
//                                  checkPath(Path prefix).
//     Nodes that fail all gates or hit a node-level bypass are excluded.
//  3. Priority short-circuit   — if the top node has strictly higher Priority
//                                (>0) than the rest and no backup flag is present,
//                                it wins directly (selector skipped).
//  4. Selector                 — Filters (FailFilter, BackupFilter) cull the pool,
//                                then Strategy (roundRobin/random/fifo/hash/parallel)
//                                picks one.
//
// Returns nil when no node survives all stages.
func (p *chainHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	var options hop.SelectOptions
	for _, opt := range opts {
		opt(&options)
	}

	log := p.logger

	// Stage 1: hop-level bypass.
	if p.options.bypass != nil &&
		p.options.bypass.Contains(ctx, options.Network, options.Addr, bypass.WithHostOption(options.Host)) {
		return nil
	}

	// Stage 2: build candidate pool — each node must pass one of two gates.
	var nodes []*chain.Node
	for _, node := range p.Nodes() {
		if node == nil {
			continue
		}
		// node level bypass
		if node.Options().Bypass != nil &&
			node.Options().Bypass.Contains(ctx, options.Network, options.Addr, bypass.WithHostOption(options.Host)) {
			continue
		}

		if matcher := node.Options().Matcher; matcher != nil {
			// Gate 2a: routing.Matcher — boolean expression on HTTP-level fields.
			// A match assigns a non-zero Priority (from rule specificity).
			req := routing.Request{
				ClientIP: options.ClientIP,
				Network:  options.Network,
				Host:     options.Host,
				Protocol: options.Protocol,
				Method:   options.Method,
				Path:     options.Path,
				Query:    options.Query,
				Header:   options.Header,
				Body:     options.Body,
			}
			if !matcher.Match(&req) {
				continue
			}
			log.Debugf("node %s match request %s %s, priority %d", node.Name, req.Protocol, req.Host, node.Options().Priority)
		} else {
			// Gate 2b: fallback eligibility — simple host/protocol/path filters.
			if !p.isEligible(node, &options) {
				continue
			}
		}

		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	// Stage 3: priority short-circuit.
	// Sort descending so the highest priority node is at index 0.
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Options().Priority > nodes[j].Options().Priority
	})

	if nodes[0].Options().Priority > 0 &&
		!anyBackupNode(nodes) &&
		nodes[0].Options().Priority > nodes[1].Options().Priority {
		// Priority short-circuit: highest-priority non-backup node wins.
		// Conditions: (1) top priority > 0 means a matcher indicated routing
		// specificity, so the top node is authoritative for this request;
		// (2) no backup node is present, otherwise BackupFilter would be
		// silently bypassed; (3) the top priority is strictly higher than
		// the second-highest — when multiple nodes share the same matcher
		// rule they have equal priority and the selector (FailFilter,
		// BackupFilter, strategy) should still apply for load balancing.
		// When all three hold the selector is skipped and the best node wins directly.
		p.logger.Debugf("priority shortcut: node %s selected", nodes[0].Name)
		return nodes[0]
	}

	// Stage 4: selector — filters then strategy.
	if s := p.options.selector; s != nil {
		return s.Select(ctx, nodes...)
	}
	return nodes[0]
}

func (p *chainHop) isEligible(node *chain.Node, opts *hop.SelectOptions) bool {
	if node == nil {
		return false
	}
	if node.Options().Filter == nil {
		return true
	}

	if !p.checkHost(opts.Host, node) || !p.checkProtocol(opts.Protocol, node) || !p.checkPath(opts.Path, node) {
		return false
	}
	return true
}

func (p *chainHop) checkHost(host string, node *chain.Node) bool {
	var vhost string
	if filter := node.Options().Filter; filter != nil {
		vhost = filter.Host
	}
	if vhost == "" { // backup node
		return true
	}

	if host == "" {
		return false
	}

	if v, _, _ := net.SplitHostPort(host); v != "" {
		host = v
	}

	if vhost == host || vhost[0] == '.' && strings.HasSuffix(host, vhost[1:]) {
		return true
	}

	return false
}

func (p *chainHop) checkProtocol(protocol string, node *chain.Node) bool {
	var prot string
	if filter := node.Options().Filter; filter != nil {
		prot = filter.Protocol
	}
	if prot == "" {
		return true
	}
	return prot == protocol
}

func (p *chainHop) checkPath(path string, node *chain.Node) bool {
	var pathFilter string
	if filter := node.Options().Filter; filter != nil {
		pathFilter = filter.Path
	}

	if pathFilter == "" {
		return true
	}

	return strings.HasPrefix(path, pathFilter)
}

func (p *chainHop) periodReload(ctx context.Context) error {
	if err := p.reload(ctx); err != nil {
		p.logger.Warnf("reload: %v", err)
	}

	period := p.options.period
	if period <= 0 {
		return nil
	}
	if period < time.Second {
		period = time.Second
	}

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.reload(ctx); err != nil {
				p.logger.Warnf("reload: %v", err)
				// return err
			}
			p.logger.Debug("hop reload done")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *chainHop) reload(ctx context.Context) (err error) {
	nodes := p.options.nodes

	nl, err := p.load(ctx)

	nodes = append(nodes, nl...)

	p.logger.Debugf("load items %d", len(nodes))

	p.mu.Lock()
	defer p.mu.Unlock()

	p.nodes = nodes

	return
}

func (p *chainHop) load(ctx context.Context) (nodes []*chain.Node, err error) {
	var errs []error

	if loader := p.options.fileLoader; loader != nil {
		r, er := loader.Load(ctx)
		if er != nil {
			p.logger.Warnf("file loader: %v", er)
			errs = append(errs, er)
		}
		ns, pe := p.parseNode(r)
		if pe != nil {
			errs = append(errs, pe)
		}
		nodes = append(nodes, ns...)
	}

	if loader := p.options.redisLoader; loader != nil {
		r, er := loader.Load(ctx)
		if er != nil {
			p.logger.Warnf("redis loader: %v", er)
			errs = append(errs, er)
		}
		ns, pe := p.parseNode(r)
		if pe != nil {
			errs = append(errs, pe)
		}
		nodes = append(nodes, ns...)
	}

	if loader := p.options.httpLoader; loader != nil {
		r, er := loader.Load(ctx)
		if er != nil {
			p.logger.Warnf("http loader: %v", er)
			errs = append(errs, er)
		}
		ns, pe := p.parseNode(r)
		if pe != nil {
			errs = append(errs, pe)
		}
		nodes = append(nodes, ns...)
	}

	return nodes, errors.Join(errs...)
}

func (p *chainHop) parseNode(r io.Reader) ([]*chain.Node, error) {
	if r == nil {
		return nil, nil
	}

	var ncs []*config.NodeConfig
	if err := json.NewDecoder(r).Decode(&ncs); err != nil {
		return nil, err
	}

	var (
		nodes []*chain.Node
		errs  []error
	)
	for _, nc := range ncs {
		if nc == nil {
			continue
		}

		node, err := node_parser.ParseNode(p.options.name, nc, logger.Default())
		if err != nil {
			p.logger.Warnf("skip node %s: %v", nc.Name, err)
			errs = append(errs, err)
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, errors.Join(errs...)
}

func (p *chainHop) Close() error {
	p.cancelFunc()
	if p.options.fileLoader != nil {
		p.options.fileLoader.Close()
	}
	if p.options.redisLoader != nil {
		p.options.redisLoader.Close()
	}
	if p.options.httpLoader != nil {
		p.options.httpLoader.Close()
	}
	return nil
}

// anyBackupNode reports whether any node in the list has the backup metadata
// flag set. Used to ensure that when backup nodes are in the candidate pool
// the priority short-circuit is disabled, forcing selection through the
// selector where BackupFilter can separate primary from failover nodes.
// Without this gate, nodes with equal non-zero priority (auto-assigned from
// matcher rule length) would skip BackupFilter entirely via the priority
// short-circuit at Select, making backup metadata a no-op.
func anyBackupNode(nodes []*chain.Node) bool {
	for _, node := range nodes {
		if md := node.Options().Metadata; md != nil && md.IsExists("backup") {
			if md.Get("backup") == true {
				return true
			}
		}
	}
	return false
}
