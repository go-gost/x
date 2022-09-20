package traffic

import (
	"bufio"
	"context"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/units"
	limiter "github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	"github.com/yl2chen/cidranger"
)

const (
	GlobalLimitKey = "$"
	ConnLimitKey   = "$$"
)

type limiterGroup struct {
	limiters []limiter.Limiter
}

func newLimiterGroup(limiters ...limiter.Limiter) *limiterGroup {
	sort.Slice(limiters, func(i, j int) bool {
		return limiters[i].Limit() < limiters[j].Limit()
	})
	return &limiterGroup{limiters: limiters}
}

func (l *limiterGroup) Wait(ctx context.Context, n int) int {
	for i := range l.limiters {
		if v := l.limiters[i].Wait(ctx, n); v < n {
			n = v
		}
	}
	return n
}

func (l *limiterGroup) Limit() int {
	if len(l.limiters) == 0 {
		return 0
	}

	return l.limiters[0].Limit()
}

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

type trafficLimiter struct {
	ipLimits   map[string]TrafficLimitGenerator
	cidrLimits cidranger.Ranger
	inLimits   map[string]limiter.Limiter
	outLimits  map[string]limiter.Limiter
	mu         sync.Mutex
	cancelFunc context.CancelFunc
	options    options
}

func NewTrafficLimiter(opts ...Option) limiter.TrafficLimiter {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	lim := &trafficLimiter{
		ipLimits:   make(map[string]TrafficLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		inLimits:   make(map[string]limiter.Limiter),
		outLimits:  make(map[string]limiter.Limiter),
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

func (l *trafficLimiter) In(key string) limiter.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if lim, ok := l.inLimits[key]; ok {
		return lim
	}

	var lims []limiter.Limiter

	if ip := net.ParseIP(key); ip != nil {
		found := false
		if p := l.ipLimits[key]; p != nil {
			if lim := p.In(); lim != nil {
				lims = append(lims, lim)
				found = true
			}
		}
		if !found {
			if p, _ := l.cidrLimits.ContainingNetworks(ip); len(p) > 0 {
				if v, _ := p[0].(*cidrLimitEntry); v != nil {
					if lim := v.limit.In(); lim != nil {
						lims = append(lims, lim)
					}
				}
			}
		}
	}

	if p := l.ipLimits[ConnLimitKey]; p != nil {
		if lim := p.In(); lim != nil {
			lims = append(lims, lim)
		}
	}
	if p := l.ipLimits[GlobalLimitKey]; p != nil {
		if lim := p.In(); lim != nil {
			lims = append(lims, lim)
		}
	}

	var lim limiter.Limiter
	if len(lims) > 0 {
		lim = newLimiterGroup(lims...)
	}
	l.inLimits[key] = lim

	if lim != nil && l.options.logger != nil {
		l.options.logger.Debugf("input limit for %s: %d", key, lim.Limit())
	}

	return lim
}

func (l *trafficLimiter) Out(key string) limiter.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if lim, ok := l.outLimits[key]; ok {
		return lim
	}

	var lims []limiter.Limiter

	if ip := net.ParseIP(key); ip != nil {
		found := false
		if p := l.ipLimits[key]; p != nil {
			if lim := p.Out(); lim != nil {
				lims = append(lims, lim)
				found = true
			}
		}
		if !found {
			if p, _ := l.cidrLimits.ContainingNetworks(ip); len(p) > 0 {
				if v, _ := p[0].(*cidrLimitEntry); v != nil {
					if lim := v.limit.Out(); lim != nil {
						lims = append(lims, lim)
					}
				}
			}
		}
	}

	if p := l.ipLimits[ConnLimitKey]; p != nil {
		if lim := p.Out(); lim != nil {
			lims = append(lims, lim)
		}
	}
	if p := l.ipLimits[GlobalLimitKey]; p != nil {
		if lim := p.Out(); lim != nil {
			lims = append(lims, lim)
		}
	}

	var lim limiter.Limiter
	if len(lims) > 0 {
		lim = newLimiterGroup(lims...)
	}
	l.outLimits[key] = lim

	if lim != nil && l.options.logger != nil {
		l.options.logger.Debugf("output limit for %s: %d", key, lim.Limit())
	}

	return lim
}

func (l *trafficLimiter) periodReload(ctx context.Context) error {
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

func (l *trafficLimiter) reload(ctx context.Context) error {
	v, err := l.load(ctx)
	if err != nil {
		return err
	}

	lines := append(l.options.limits, v...)

	ipLimits := make(map[string]TrafficLimitGenerator)
	cidrLimits := cidranger.NewPCTrieRanger()

	for _, s := range lines {
		key, in, out := l.parseLimit(s)
		if key == "" {
			continue
		}
		switch key {
		case GlobalLimitKey:
			ipLimits[key] = NewTrafficLimitSingleGenerator(in, out)
		case ConnLimitKey:
			ipLimits[key] = NewTrafficLimitGenerator(in, out)
		default:
			if ip := net.ParseIP(key); ip != nil {
				ipLimits[key] = NewTrafficLimitGenerator(in, out)
				break
			}
			if _, ipNet, _ := net.ParseCIDR(key); ipNet != nil {
				cidrLimits.Insert(&cidrLimitEntry{
					ipNet: *ipNet,
					limit: NewTrafficLimitGenerator(in, out),
				})
			}
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.ipLimits = ipLimits
	l.cidrLimits = cidrLimits
	l.inLimits = make(map[string]limiter.Limiter)
	l.outLimits = make(map[string]limiter.Limiter)

	return nil
}

func (l *trafficLimiter) load(ctx context.Context) (patterns []string, err error) {
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

func (l *trafficLimiter) parsePatterns(r io.Reader) (patterns []string, err error) {
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

func (l *trafficLimiter) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

func (l *trafficLimiter) parseLimit(s string) (key string, in, out int) {
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
	if v, _ := units.ParseBase2Bytes(ss[1]); v > 0 {
		in = int(v)
	}
	if len(ss) > 2 {
		if v, _ := units.ParseBase2Bytes(ss[2]); v > 0 {
			out = int(v)
		}
	}

	return
}

func (l *trafficLimiter) Close() error {
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
	limit TrafficLimitGenerator
}

func (p *cidrLimitEntry) Network() net.IPNet {
	return p.ipNet
}
