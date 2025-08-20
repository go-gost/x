package bypass

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/matcher"
	xnet "github.com/go-gost/x/internal/net"
	xlogger "github.com/go-gost/x/logger"
	"github.com/gobwas/glob"
)

var (
	ErrBypass = errors.New("bypass")
)

type options struct {
	whitelist   bool
	matchers    []string
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	logger      logger.Logger
}

type Option func(opts *options)

func WhitelistOption(whitelist bool) Option {
	return func(opts *options) {
		opts.whitelist = whitelist
	}
}

func MatchersOption(matchers []string) Option {
	return func(opts *options) {
		opts.matchers = matchers
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

type localBypass struct {
	cidrMatcher     matcher.Matcher
	addrMatcher     matcher.Matcher
	wildcardMatcher matcher.Matcher
	ipRangeMatcher  matcher.Matcher
	options         options
	logger          logger.Logger
	mu              sync.RWMutex
	cancelFunc      context.CancelFunc
}

// NewBypass creates and initializes a new Bypass.
// The rules will be reversed if the reverse option is true.
func NewBypass(opts ...Option) bypass.Bypass {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &localBypass{
		cidrMatcher:     matcher.NopMatcher(),
		addrMatcher:     matcher.NopMatcher(),
		wildcardMatcher: matcher.NopMatcher(),
		ipRangeMatcher:  matcher.NopMatcher(),
		cancelFunc:      cancel,
		options:         options,
		logger:          options.logger,
	}
	if p.logger == nil {
		p.logger = xlogger.Nop()
	}

	go p.periodReload(ctx)

	return p
}

func (p *localBypass) periodReload(ctx context.Context) error {
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
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *localBypass) reload(ctx context.Context) error {
	v, err := p.load(ctx)
	if err != nil {
		return err
	}
	patterns := append(p.options.matchers, v...)
	p.logger.Debugf("load items %d", len(patterns))

	var addrs []string
	var inets []*net.IPNet
	var wildcards []string
	var ipRanges []xnet.IPRange
	for _, pattern := range patterns {
		if _, inet, err := net.ParseCIDR(pattern); err == nil {
			inets = append(inets, inet)
			continue
		}

		if strings.ContainsAny(pattern, "*?") {
			if _, err := glob.Compile(pattern); err == nil {
				wildcards = append(wildcards, pattern)
				continue
			}
		}

		r := xnet.IPRange{}
		if err := r.Parse(pattern); err == nil {
			ipRanges = append(ipRanges, r)
			continue
		}

		addrs = append(addrs, pattern)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.cidrMatcher = matcher.CIDRMatcher(inets)
	p.addrMatcher = matcher.AddrMatcher(addrs)
	p.wildcardMatcher = matcher.WildcardMatcher(wildcards)
	p.ipRangeMatcher = matcher.IPRangeMatcher(ipRanges)

	return nil
}

func (p *localBypass) load(ctx context.Context) (patterns []string, err error) {
	if p.options.fileLoader != nil {
		if lister, ok := p.options.fileLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				p.logger.Warnf("file loader: %v", er)
			}
			for _, s := range list {
				if line := p.parseLine(s); line != "" {
					patterns = append(patterns, line)
				}
			}
		} else {
			r, er := p.options.fileLoader.Load(ctx)
			if er != nil {
				p.logger.Warnf("file loader: %v", er)
			}
			if v, _ := p.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if p.options.redisLoader != nil {
		if lister, ok := p.options.redisLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				p.logger.Warnf("redis loader: %v", er)
			}
			patterns = append(patterns, list...)
		} else {
			r, er := p.options.redisLoader.Load(ctx)
			if er != nil {
				p.logger.Warnf("redis loader: %v", er)
			}
			if v, _ := p.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if p.options.httpLoader != nil {
		r, er := p.options.httpLoader.Load(ctx)
		if er != nil {
			p.logger.Warnf("http loader: %v", er)
		}
		if v, _ := p.parsePatterns(r); v != nil {
			patterns = append(patterns, v...)
		}
	}

	return
}

func (p *localBypass) parsePatterns(r io.Reader) (patterns []string, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if line := p.parseLine(scanner.Text()); line != "" {
			patterns = append(patterns, line)
		}
	}

	err = scanner.Err()
	return
}

func (p *localBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if addr == "" || p == nil {
		return false
	}

	matched := p.matched(addr)

	b := !p.options.whitelist && matched ||
		p.options.whitelist && !matched

	log := p.logger.WithFields(map[string]any{
		"sid": ctxvalue.SidFromContext(ctx),
	})

	if b {
		log.Debugf("bypass: %s, whitelist: %t", addr, p.options.whitelist)
	} else {
		log.Debugf("pass: %s, whitelist: %t", addr, p.options.whitelist)
	}
	return b
}

func (p *localBypass) IsWhitelist() bool {
	return p.options.whitelist
}

func (p *localBypass) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

func (p *localBypass) matched(addr string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.ipRangeMatcher.Match(addr) {
		return true
	}

	if p.addrMatcher.Match(addr) {
		return true
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	if ip := net.ParseIP(host); ip != nil && p.cidrMatcher.Match(host) {
		return true
	}

	return p.wildcardMatcher.Match(addr)
}

func (p *localBypass) Close() error {
	p.cancelFunc()
	if p.options.fileLoader != nil {
		p.options.fileLoader.Close()
	}
	if p.options.redisLoader != nil {
		p.options.redisLoader.Close()
	}
	return nil
}

type bypassGroup struct {
	bypasses []bypass.Bypass
}

func BypassGroup(bypasses ...bypass.Bypass) bypass.Bypass {
	return &bypassGroup{
		bypasses: bypasses,
	}
}

func (p *bypassGroup) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	var whitelist, blacklist []bool
	for _, bypass := range p.bypasses {
		result := bypass.Contains(ctx, network, addr, opts...)
		if bypass.IsWhitelist() {
			whitelist = append(whitelist, result)
		} else {
			blacklist = append(blacklist, result)
		}
	}
	status := false
	if len(whitelist) > 0 {
		if slices.Contains(whitelist, false) {
			status = false
		} else {
			status = true
		}
	}
	if !status && len(blacklist) > 0 {
		if slices.Contains(blacklist, true) {
			status = true
		} else {
			status = false
		}
	}
	return status
}

func (p *bypassGroup) IsWhitelist() bool {
	return false
}
