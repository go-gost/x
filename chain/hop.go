package chain

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/x/internal/loader"
)

type HopOptions struct {
	bypass      bypass.Bypass
	selector    selector.Selector[*chain.Node]
	fileLoader  loader.Loader
	httpLoader  loader.Loader
	redisLoader loader.Loader
	period      time.Duration
	logger      logger.Logger
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

func FileLoaderHopOption(fileLoader loader.Loader) HopOption {
	return func(opts *HopOptions) {
		opts.fileLoader = fileLoader
	}
}

func RedisLoaderHopOption(redisLoader loader.Loader) HopOption {
	return func(opts *HopOptions) {
		opts.redisLoader = redisLoader
	}
}

func HTTPLoaderHopOption(httpLoader loader.Loader) HopOption {
	return func(opts *HopOptions) {
		opts.httpLoader = httpLoader
	}
}

func ReloadPeriodHopOption(period time.Duration) HopOption {
	return func(opts *HopOptions) {
		opts.period = period
	}
}

func LoggerHopOption(logger logger.Logger) HopOption {
	return func(opts *HopOptions) {
		opts.logger = logger
	}
}

type chainHop struct {
	nodes      []*chain.Node
	options    HopOptions
	cancelFunc context.CancelFunc
	mu         sync.RWMutex
}

func NewChainHop(nodes []*chain.Node, opts ...HopOption) chain.Hop {
	var options HopOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	ctx, cancel := context.WithCancel(context.TODO())

	hop := &chainHop{
		nodes:      nodes,
		options:    options,
		cancelFunc: cancel,
	}
	if err := hop.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if hop.options.period > 0 {
		go hop.periodReload(ctx)
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
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *chainHop) reload(ctx context.Context) error {
	_, err := p.load(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (p *chainHop) load(ctx context.Context) (data []byte, err error) {
	if p.options.fileLoader != nil {
		r, er := p.options.fileLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("file loader: %v", er)
		}
		return io.ReadAll(r)
	}

	if p.options.redisLoader != nil {
		r, er := p.options.redisLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("redis loader: %v", er)
		}
		return io.ReadAll(r)
	}

	if p.options.httpLoader != nil {
		r, er := p.options.redisLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("http loader: %v", er)
		}
		return io.ReadAll(r)
	}

	return
}
