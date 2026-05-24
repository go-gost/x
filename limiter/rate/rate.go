// Package rate implements a rate limiter with support for global, per-IP,
// and CIDR-based rate limits with periodic hot-reload from file, Redis, or HTTP sources.
package rate

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	limiter "github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
	"github.com/yl2chen/cidranger"
)

const (
	// GlobalLimitKey is the key used to configure a global rate limit that applies to all traffic.
	GlobalLimitKey = "$"
	// IPLimitKey is the key used to configure a per-IP rate limit where each unique IP
	// gets its own independent rate limiter.
	IPLimitKey = "$$"
)

type options struct {
	limits      []string
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	logger      logger.Logger
}

// Option configures a [rateLimiter].
type Option func(opts *options)

// LimitsOption sets the static rate limit rules as strings in "key limit" format
// (e.g., "$ 100", "192.168.1.1 50", "10.0.0.0/8 30").
func LimitsOption(limits ...string) Option {
	return func(opts *options) {
		opts.limits = limits
	}
}

// ReloadPeriodOption sets the period for periodic reload of rate limit rules
// from external loaders. If zero or negative, periodic reload is disabled.
// Values less than one second are clamped to one second.
func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

// FileLoaderOption sets the file-based [loader.Loader] for rate limit rules.
func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

// RedisLoaderOption sets the Redis-based [loader.Loader] for rate limit rules.
func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

// HTTPLoaderOption sets the HTTP-based [loader.Loader] for rate limit rules.
func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}

// LoggerOption sets the [logger.Logger] for the rate limiter.
// If not set, a no-op logger is used.
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type rateLimiter struct {
	ipLimits   map[string]RateLimitGenerator
	cidrLimits cidranger.Ranger
	limits     map[string]limiter.Limiter
	mu         sync.Mutex
	cancelFunc context.CancelFunc
	options    options
	logger     logger.Logger
}

// NewRateLimiter creates a [limiter.RateLimiter] with the given options.
// It starts a background goroutine for periodic reload and returns an
// implementation that supports global, per-IP, and CIDR-based rate limits.
func NewRateLimiter(opts ...Option) limiter.RateLimiter {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	lim := &rateLimiter{
		ipLimits:   make(map[string]RateLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		limits:     make(map[string]limiter.Limiter),
		options:    options,
		cancelFunc: cancel,
		logger:     options.logger,
	}
	if lim.logger == nil {
		lim.logger = xlogger.Nop()
	}

	go lim.periodReload(ctx)

	return lim
}

func (l *rateLimiter) Limiter(key string) limiter.Limiter {
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

	if lim != nil && l.logger != nil {
		l.logger.Debugf("input limit for %s: %d", key, lim.Limit())
	}

	return lim
}

func (l *rateLimiter) periodReload(ctx context.Context) error {
	if err := l.reload(ctx); err != nil {
		l.logger.Warnf("reload: %v", err)
	}

	period := l.options.period
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
			if err := l.reload(ctx); err != nil {
				l.logger.Warnf("reload: %v", err)
				// return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *rateLimiter) reload(ctx context.Context) error {
	v, err := l.load(ctx)
	if err != nil {
		return err
	}

	lines := append(l.options.limits, v...)

	ipLimits := make(map[string]RateLimitGenerator)
	cidrLimits := cidranger.NewPCTrieRanger()

	for _, s := range lines {
		key, limit := l.parseLimit(s)
		if key == "" || limit <= 0 {
			continue
		}
		switch key {
		case GlobalLimitKey:
			ipLimits[key] = NewRateLimitSingleGenerator(limit)
		case IPLimitKey:
			ipLimits[key] = NewRateLimitGenerator(limit)
		default:
			if ip := net.ParseIP(key); ip != nil {
				ipLimits[key] = NewRateLimitSingleGenerator(limit)
				break
			}
			if _, ipNet, _ := net.ParseCIDR(key); ipNet != nil {
				cidrLimits.Insert(&cidrLimitEntry{
					ipNet: *ipNet,
					limit: NewRateLimitGenerator(limit),
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

func (l *rateLimiter) load(ctx context.Context) (patterns []string, err error) {
	if l.options.fileLoader != nil {
		if lister, ok := l.options.fileLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				l.logger.Warnf("file loader: %v", er)
			}
			for _, s := range list {
				if line := l.parseLine(s); line != "" {
					patterns = append(patterns, line)
				}
			}
		} else {
			r, er := l.options.fileLoader.Load(ctx)
			if er != nil {
				l.logger.Warnf("file loader: %v", er)
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
				l.logger.Warnf("redis loader: %v", er)
			}
			patterns = append(patterns, list...)
		} else {
			r, er := l.options.redisLoader.Load(ctx)
			if er != nil {
				l.logger.Warnf("redis loader: %v", er)
			}
			if v, _ := l.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if l.options.httpLoader != nil {
		r, er := l.options.httpLoader.Load(ctx)
		if er != nil {
			l.logger.Warnf("http loader: %v", er)
		}
		if v, _ := l.parsePatterns(r); v != nil {
			patterns = append(patterns, v...)
		}
	}

	l.logger.Debugf("load items %d", len(patterns))
	return
}

func (l *rateLimiter) parsePatterns(r io.Reader) (patterns []string, err error) {
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

func (l *rateLimiter) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

func (l *rateLimiter) parseLimit(s string) (key string, limit float64) {
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
	limit, _ = strconv.ParseFloat(ss[1], 64)

	return
}

func (l *rateLimiter) Close() error {
	l.cancelFunc()
	if l.options.fileLoader != nil {
		l.options.fileLoader.Close()
	}
	if l.options.redisLoader != nil {
		l.options.redisLoader.Close()
	}
	if l.options.httpLoader != nil {
		l.options.httpLoader.Close()
	}
	return nil
}

type cidrLimitEntry struct {
	ipNet net.IPNet
	limit RateLimitGenerator
}

func (p *cidrLimitEntry) Network() net.IPNet {
	return p.ipNet
}
