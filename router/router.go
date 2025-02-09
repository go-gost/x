package router

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/router"
	"github.com/go-gost/x/internal/loader"
)

type options struct {
	routes      []*router.Route
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	logger      logger.Logger
}

type Option func(opts *options)

func RoutesOption(routes []*router.Route) Option {
	return func(opts *options) {
		opts.routes = routes
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

type localRouter struct {
	routes     []*router.Route
	cancelFunc context.CancelFunc
	options    options
	mu         sync.RWMutex
}

// NewRouter creates and initializes a new Router.
func NewRouter(opts ...Option) router.Router {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())

	r := &localRouter{
		cancelFunc: cancel,
		options:    options,
	}

	if err := r.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if r.options.period > 0 {
		go r.periodReload(ctx)
	}

	return r
}

func (p *localRouter) periodReload(ctx context.Context) error {
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

func (p *localRouter) reload(ctx context.Context) error {
	routes := p.options.routes

	v, err := p.load(ctx)
	if err != nil {
		return err
	}
	routes = append(routes, v...)

	p.options.logger.Debugf("load items %d", len(routes))

	if err := p.setSysRoutes(routes...); err != nil {
		p.options.logger.Error(err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.routes = routes

	return nil
}

func (p *localRouter) load(ctx context.Context) (routes []*router.Route, err error) {
	if p.options.fileLoader != nil {
		if lister, ok := p.options.fileLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				p.options.logger.Warnf("file loader: %v", er)
			}
			for _, s := range list {
				routes = append(routes, p.parseLine(s))
			}
		} else {
			fr, er := p.options.fileLoader.Load(ctx)
			if er != nil {
				p.options.logger.Warnf("file loader: %v", er)
			}
			if v, _ := p.parseRoutes(fr); v != nil {
				routes = append(routes, v...)
			}
		}
	}
	if p.options.redisLoader != nil {
		if lister, ok := p.options.redisLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				p.options.logger.Warnf("redis loader: %v", er)
			}
			for _, v := range list {
				routes = append(routes, p.parseLine(v))
			}
		} else {
			r, er := p.options.redisLoader.Load(ctx)
			if er != nil {
				p.options.logger.Warnf("redis loader: %v", er)
			}
			v, _ := p.parseRoutes(r)
			routes = append(routes, v...)
		}
	}
	if p.options.httpLoader != nil {
		r, er := p.options.httpLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("http loader: %v", er)
		}
		v, _ := p.parseRoutes(r)
		routes = append(routes, v...)
	}

	return
}

func (p *localRouter) parseRoutes(r io.Reader) (routes []*router.Route, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if route := p.parseLine(scanner.Text()); route != nil {
			routes = append(routes, route)
		}
	}

	err = scanner.Err()
	return
}

func (p *localRouter) GetRoute(ctx context.Context, dst string, opts ...router.Option) *router.Route {
	if dst == "" || p == nil {
		return nil
	}

	dstIP := net.ParseIP(dst)

	p.mu.RLock()
	routes := p.routes
	p.mu.RUnlock()

	for _, route := range routes {
		if route.Dst == dst || route.Net != nil && route.Net.Contains(dstIP) {
			return route
		}
	}
	return nil
}

func (*localRouter) parseLine(s string) (route *router.Route) {
	line := strings.Replace(s, "\t", " ", -1)
	line = strings.TrimSpace(line)
	if n := strings.IndexByte(line, '#'); n >= 0 {
		line = line[:n]
	}
	var sp []string
	for _, s := range strings.Split(line, " ") {
		if s = strings.TrimSpace(s); s != "" {
			sp = append(sp, s)
		}
	}
	if len(sp) < 2 {
		return // invalid lines are ignored
	}

	return ParseRoute(sp[0], sp[1])
}

func (p *localRouter) Close() error {
	p.cancelFunc()
	if p.options.fileLoader != nil {
		p.options.fileLoader.Close()
	}
	if p.options.redisLoader != nil {
		p.options.redisLoader.Close()
	}
	return nil
}

func ParseRoute(dst string, gateway string) *router.Route {
	if dst == "" {
		return nil
	}
	_, ipNet, _ := net.ParseCIDR(dst)

	return &router.Route{
		Net:     ipNet,
		Dst:     dst,
		Gateway: gateway,
	}
}
