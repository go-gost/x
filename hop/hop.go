package hop

import (
	"context"
	"encoding/json"
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
	"github.com/go-gost/core/selector"
	"github.com/go-gost/x/config"
	node_parser "github.com/go-gost/x/config/parsing/node"
	"github.com/go-gost/x/internal/loader"
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

type Option func(*options)

func NameOption(name string) Option {
	return func(o *options) {
		o.name = name
	}
}

func NodeOption(nodes ...*chain.Node) Option {
	return func(o *options) {
		o.nodes = nodes
	}
}
func BypassOption(bp bypass.Bypass) Option {
	return func(o *options) {
		o.bypass = bp
	}
}

func SelectorOption(s selector.Selector[*chain.Node]) Option {
	return func(o *options) {
		o.selector = s
	}
}

func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type chainHop struct {
	nodes      []*chain.Node
	mu         sync.RWMutex
	cancelFunc context.CancelFunc
	options    options
}

func NewHop(opts ...Option) hop.Hop {
	var options options
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	ctx, cancel := context.WithCancel(context.TODO())
	p := &chainHop{
		cancelFunc: cancel,
		options:    options,
	}

	if err := p.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if p.options.period > 0 {
		go p.periodReload(ctx)
	}

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

func (p *chainHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	var options hop.SelectOptions
	for _, opt := range opts {
		opt(&options)
	}

	// hop level bypass
	if p.options.bypass != nil &&
		p.options.bypass.Contains(ctx, options.Network, options.Addr, bypass.WithHostOpton(options.Host)) {
		return nil
	}

	filters := p.filterByHost(options.Host, p.Nodes()...)
	filters = p.filterByProtocol(options.Protocol, filters...)
	filters = p.filterByPath(options.Path, filters...)

	var nodes []*chain.Node
	for _, node := range filters {
		if node == nil {
			continue
		}
		// node level bypass
		if node.Options().Bypass != nil &&
			node.Options().Bypass.Contains(ctx, options.Network, options.Addr, bypass.WithHostOpton(options.Host)) {
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

func (p *chainHop) filterByHost(host string, nodes ...*chain.Node) (filters []*chain.Node) {
	if host == "" || len(nodes) == 0 {
		return nodes
	}

	if v, _, _ := net.SplitHostPort(host); v != "" {
		host = v
	}
	p.options.logger.Debugf("filter by host: %s", host)

	found := false
	for _, node := range nodes {
		if node == nil {
			continue
		}

		var vhost string
		if filter := node.Options().Filter; filter != nil {
			vhost = filter.Host
		}
		if vhost == "" { // backup node
			if !found {
				filters = append(filters, node)
			}
			continue
		}

		if vhost == host ||
			vhost[0] == '.' && strings.HasSuffix(host, vhost[1:]) {
			if !found { // clear all backup nodes when matched node found
				filters = nil
			}
			filters = append(filters, node)
			found = true
			continue
		}

	}

	return
}

func (p *chainHop) filterByProtocol(protocol string, nodes ...*chain.Node) (filters []*chain.Node) {
	if protocol == "" || len(nodes) == 0 {
		return nodes
	}

	p.options.logger.Debugf("filter by protocol: %s", protocol)
	found := false
	for _, node := range nodes {
		if node == nil {
			continue
		}

		var prot string
		if filter := node.Options().Filter; filter != nil {
			prot = filter.Protocol
		}
		if prot == "" {
			if !found {
				filters = append(filters, node)
			}
			continue
		}

		if prot == protocol {
			if !found {
				filters = nil
			}
			filters = append(filters, node)
			found = true
			continue
		}
	}

	return
}

func (p *chainHop) filterByPath(path string, nodes ...*chain.Node) (filters []*chain.Node) {
	if path == "" || len(nodes) == 0 {
		return nodes
	}

	p.options.logger.Debugf("filter by path: %s", path)

	sort.SliceStable(nodes, func(i, j int) bool {
		filter1 := nodes[i].Options().Filter
		if filter1 == nil {
			return false
		}
		filter2 := nodes[j].Options().Filter
		if filter2 == nil {
			return true
		}
		return len(filter1.Path) > len(filter2.Path)
	})

	found := false
	for _, node := range nodes {
		var pathFilter string
		if filter := node.Options().Filter; filter != nil {
			pathFilter = filter.Path
		}
		if pathFilter == "" {
			if !found {
				filters = append(filters, node)
			}
			continue
		}

		if strings.HasPrefix(path, pathFilter) {
			if !found {
				filters = nil
			}
			filters = append(filters, node)
			break
		}
	}

	return
}

func (p *chainHop) periodReload(ctx context.Context) error {
	period := p.options.period
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.reload(ctx); err != nil {
				p.options.logger.Warnf("reload: %v", err)
				// return err
			}
			p.options.logger.Debug("hop reload done")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *chainHop) reload(ctx context.Context) (err error) {
	nodes := p.options.nodes

	nl, err := p.load(ctx)

	nodes = append(nodes, nl...)

	p.options.logger.Debugf("load items %d", len(nodes))

	p.mu.Lock()
	defer p.mu.Unlock()

	p.nodes = nodes

	return
}

func (p *chainHop) load(ctx context.Context) (nodes []*chain.Node, err error) {
	if loader := p.options.fileLoader; loader != nil {
		r, er := loader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("file loader: %v", er)
		}
		nodes, _ = p.parseNode(r)
	}

	if loader := p.options.redisLoader; loader != nil {
		r, er := loader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("redis loader: %v", er)
		}
		ns, _ := p.parseNode(r)
		nodes = append(nodes, ns...)
	}

	if loader := p.options.httpLoader; loader != nil {
		r, er := loader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("http loader: %v", er)
		}
		if ns, _ := p.parseNode(r); ns != nil {
			nodes = append(nodes, ns...)
		}
	}

	return
}

func (p *chainHop) parseNode(r io.Reader) ([]*chain.Node, error) {
	if r == nil {
		return nil, nil
	}

	var ncs []*config.NodeConfig
	if err := json.NewDecoder(r).Decode(&ncs); err != nil {
		return nil, err
	}

	var nodes []*chain.Node
	for _, nc := range ncs {
		if nc == nil {
			continue
		}

		node, err := node_parser.ParseNode(p.options.name, nc, logger.Default())
		if err != nil {
			return nodes, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func (p *chainHop) Close() error {
	p.cancelFunc()
	if p.options.fileLoader != nil {
		p.options.fileLoader.Close()
	}
	if p.options.redisLoader != nil {
		p.options.redisLoader.Close()
	}
	return nil
}
