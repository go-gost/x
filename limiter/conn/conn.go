package conn

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	limiter "github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	"github.com/yl2chen/cidranger"
)

const (
	GlobalLimitKey = "$"
	IPLimitKey     = "$$"
)

type options struct {
	limits      []string
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	logger      logger.Logger
}

type Option func(opts *options)

func LimitsOption(limits ...string) Option {
	return func(opts *options) {
		opts.limits = limits
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

type connLimiter struct {
	ipLimits   map[string]ConnLimitGenerator
	cidrLimits cidranger.Ranger
	limits     map[string]limiter.Limiter
	mu         sync.Mutex
	cancelFunc context.CancelFunc
	options    options
}

func NewConnLimiter(opts ...Option) limiter.ConnLimiter {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	lim := &connLimiter{
		ipLimits:   make(map[string]ConnLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		limits:     make(map[string]limiter.Limiter),
		options:    options,
		cancelFunc: cancel,
	}

	if err := lim.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if lim.options.period > 0 {
		go lim.periodReload(ctx)
	}
	return lim
}

func (l *connLimiter) Limiter(key string) limiter.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if lim, ok := l.limits[key]; ok {
		return lim
	}

	var lims []limiter.Limiter

	if ip := net.ParseIP(key); ip != nil {
		found := false
		if p := l.ipLimits[key]; p != nil {
			if lim := p.Limiter(); lim != nil {
				lims = append(lims, lim)
				found = true
			}
		}
		if !found {
			if p, _ := l.cidrLimits.ContainingNetworks(ip); len(p) > 0 {
				if v, _ := p[0].(*cidrLimitEntry); v != nil {
					if lim := v.limit.Limiter(); lim != nil {
						lims = append(lims, lim)
					}
				}
			}
		}
	}

	if len(lims) == 0 {
		if p := l.ipLimits[IPLimitKey]; p != nil {
			if lim := p.Limiter(); lim != nil {
				lims = append(lims, lim)
			}
		}
	}

	if p := l.ipLimits[GlobalLimitKey]; p != nil {
		if lim := p.Limiter(); lim != nil {
			lims = append(lims, lim)
		}
	}

	var lim limiter.Limiter
	if len(lims) > 0 {
		lim = newLimiterGroup(lims...)
	}
	l.limits[key] = lim

	if lim != nil && l.options.logger != nil {
		l.options.logger.Debugf("conn limit for %s: %d", key, lim.Limit())
	}

	return lim
}

func (l *connLimiter) periodReload(ctx context.Context) error {
	period := l.options.period
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := l.reload(ctx); err != nil {
				l.options.logger.Warnf("reload: %v", err)
				// return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *connLimiter) reload(ctx context.Context) error {
	v, err := l.load(ctx)
	if err != nil {
		return err
	}

	lines := append(l.options.limits, v...)

	ipLimits := make(map[string]ConnLimitGenerator)
	cidrLimits := cidranger.NewPCTrieRanger()

	for _, s := range lines {
		key, limit := l.parseLimit(s)
		if key == "" || limit <= 0 {
			continue
		}
		switch key {
		case GlobalLimitKey:
			ipLimits[key] = NewConnLimitSingleGenerator(limit)
		case IPLimitKey:
			ipLimits[key] = NewConnLimitGenerator(limit)
		default:
			if ip := net.ParseIP(key); ip != nil {
				ipLimits[key] = NewConnLimitSingleGenerator(limit)
				break
			}
			if _, ipNet, _ := net.ParseCIDR(key); ipNet != nil {
				cidrLimits.Insert(&cidrLimitEntry{
					ipNet: *ipNet,
					limit: NewConnLimitGenerator(limit),
				})
			}
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.ipLimits = ipLimits
	l.cidrLimits = cidrLimits
	l.limits = make(map[string]limiter.Limiter)

	return nil
}

func (l *connLimiter) load(ctx context.Context) (patterns []string, err error) {
	if l.options.fileLoader != nil {
		if lister, ok := l.options.fileLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				l.options.logger.Warnf("file loader: %v", er)
			}
			for _, s := range list {
				if line := l.parseLine(s); line != "" {
					patterns = append(patterns, line)
				}
			}
		} else {
			r, er := l.options.fileLoader.Load(ctx)
			if er != nil {
				l.options.logger.Warnf("file loader: %v", er)
			}
			if v, _ := l.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if l.options.redisLoader != nil {
		if lister, ok := l.options.redisLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				l.options.logger.Warnf("redis loader: %v", er)
			}
			patterns = append(patterns, list...)
		} else {
			r, er := l.options.redisLoader.Load(ctx)
			if er != nil {
				l.options.logger.Warnf("redis loader: %v", er)
			}
			if v, _ := l.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if l.options.httpLoader != nil {
		r, er := l.options.httpLoader.Load(ctx)
		if er != nil {
			l.options.logger.Warnf("http loader: %v", er)
		}
		if v, _ := l.parsePatterns(r); v != nil {
			patterns = append(patterns, v...)
		}
	}

	l.options.logger.Debugf("load items %d", len(patterns))
	return
}

func (l *connLimiter) parsePatterns(r io.Reader) (patterns []string, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if line := l.parseLine(scanner.Text()); line != "" {
			patterns = append(patterns, line)
		}
	}

	err = scanner.Err()
	return
}

func (l *connLimiter) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

func (l *connLimiter) parseLimit(s string) (key string, limit int) {
	s = strings.Replace(s, "\t", " ", -1)
	s = strings.TrimSpace(s)
	var ss []string
	for _, v := range strings.Split(s, " ") {
		if v != "" {
			ss = append(ss, v)
		}
	}
	if len(ss) < 2 {
		return
	}

	key = ss[0]
	limit, _ = strconv.Atoi(ss[1])

	return
}

func (l *connLimiter) Close() error {
	l.cancelFunc()
	if l.options.fileLoader != nil {
		l.options.fileLoader.Close()
	}
	if l.options.redisLoader != nil {
		l.options.redisLoader.Close()
	}
	return nil
}

type cidrLimitEntry struct {
	ipNet net.IPNet
	limit ConnLimitGenerator
}

func (p *cidrLimitEntry) Network() net.IPNet {
	return p.ipNet
}
