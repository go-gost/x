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
	xlogger "github.com/go-gost/x/logger"

	"github.com/go-gost/x/internal/loader"
)

type options struct {
	routes      []*router.Route
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	noSysRoute  bool
	logger      logger.Logger
}

// Option is a functional option for configuring a Router.
type Option func(opts *options)

// RoutesOption sets the static routes for the router.
func RoutesOption(routes []*router.Route) Option {
	return func(opts *options) {
		opts.routes = routes
	}
}

// ReloadPeriodOption sets the interval for periodic route reloading.
func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

// FileLoaderOption sets the file-based loader for route data.
func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

// RedisLoaderOption sets the Redis-based loader for route data.
func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

// HTTPLoaderOption sets the HTTP-based loader for route data.
func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}

// NoSysRouteOption disables automatic system route management via netlink.
// When set, the router only maintains in-memory routes for GetRoute lookups
// and does not attempt to add or replace routes in the OS routing table.
// This is useful when another component (e.g. a TUN listener) manages system
// routes independently.
func NoSysRouteOption() Option {
	return func(opts *options) {
		opts.noSysRoute = true
	}
}

// LoggerOption sets the logger for the router.
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

// localRouter is the built-in Router implementation. It manages static routes
// loaded from config and dynamic routes loaded from external sources (file,
// Redis, HTTP), with support for periodic hot-reload.
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
	if options.logger == nil {
		options.logger = xlogger.Nop()
	}

	ctx, cancel := context.WithCancel(context.Background())

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

// periodReload periodically reloads routes from external sources until the
// context is cancelled.
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
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// reload loads routes from all configured sources and updates the local state.
func (p *localRouter) reload(ctx context.Context) error {
	routes := p.options.routes

	v, err := p.load(ctx)
	if err != nil {
		return err
	}
	routes = append(routes, v...)

	p.options.logger.Debugf("load items %d", len(routes))

	if !p.options.noSysRoute {
		if err := p.setSysRoutes(routes...); err != nil {
			p.options.logger.Error(err)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.routes = routes

	return nil
}

// load reads routes from all configured external loaders (file, Redis, HTTP).
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
			if fr != nil {
				if v, er := p.parseRoutes(fr); er != nil {
					p.options.logger.Warnf("file loader parse: %v", er)
				} else if v != nil {
					routes = append(routes, v...)
				}
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
			if r != nil {
				if v, er := p.parseRoutes(r); er != nil {
					p.options.logger.Warnf("redis loader parse: %v", er)
				} else {
					routes = append(routes, v...)
				}
			}
		}
	}
	if p.options.httpLoader != nil {
		r, er := p.options.httpLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("http loader: %v", er)
		}
		if r != nil {
			if v, er := p.parseRoutes(r); er != nil {
				p.options.logger.Warnf("http loader parse: %v", er)
			} else {
				routes = append(routes, v...)
			}
		}
	}

	return
}

// parseRoutes reads routes from an io.Reader, one route per line.
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

// GetRoute returns the route matching the given destination address. It matches
// by exact destination string or by CIDR network containment.
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

// parseLine parses a single route line in "destination gateway" format.
// Comments (prefixed with #) and blank lines are ignored.
func (*localRouter) parseLine(s string) (route *router.Route) {
	line := strings.ReplaceAll(s, "\t", " ")
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
		return
	}

	return ParseRoute(sp[0], sp[1])
}

// Close stops the periodic reload goroutine and closes all configured loaders.
func (p *localRouter) Close() error {
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

// ParseRoute parses a destination/gateway pair into a Route. The destination
// may be a CIDR notation network (e.g. "10.0.0.0/8") or a plain address. If dst
// is empty, nil is returned.
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
