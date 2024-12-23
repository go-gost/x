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
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/matcher"
	xnet "github.com/go-gost/x/internal/net"
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
	cancelFunc      context.CancelFunc
	options         options
	mu              sync.RWMutex
}

// NewBypass creates and initializes a new Bypass.
// The rules will be reversed if the reverse option is true.
func NewBypass(opts ...Option) bypass.Bypass {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())

	bp := &localBypass{
		cancelFunc: cancel,
		options:    options,
	}

	if err := bp.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if bp.options.period > 0 {
		go bp.periodReload(ctx)
	}

	return bp
}

func (bp *localBypass) periodReload(ctx context.Context) error {
	period := bp.options.period
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := bp.reload(ctx); err != nil {
				bp.options.logger.Warnf("reload: %v", err)
				// return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (bp *localBypass) reload(ctx context.Context) error {
	v, err := bp.load(ctx)
	if err != nil {
		return err
	}
	patterns := append(bp.options.matchers, v...)
	bp.options.logger.Debugf("load items %d", len(patterns))

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
			wildcards = append(wildcards, pattern)
			continue
		}

		r := xnet.IPRange{}
		if err := r.Parse(pattern); err == nil {
			ipRanges = append(ipRanges, r)
			continue
		}

		addrs = append(addrs, pattern)
	}

	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.cidrMatcher = matcher.CIDRMatcher(inets)
	bp.addrMatcher = matcher.AddrMatcher(addrs)
	bp.wildcardMatcher = matcher.WildcardMatcher(wildcards)
	bp.ipRangeMatcher = matcher.IPRangeMatcher(ipRanges)

	return nil
}

func (bp *localBypass) load(ctx context.Context) (patterns []string, err error) {
	if bp.options.fileLoader != nil {
		if lister, ok := bp.options.fileLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				bp.options.logger.Warnf("file loader: %v", er)
			}
			for _, s := range list {
				if line := bp.parseLine(s); line != "" {
					patterns = append(patterns, line)
				}
			}
		} else {
			r, er := bp.options.fileLoader.Load(ctx)
			if er != nil {
				bp.options.logger.Warnf("file loader: %v", er)
			}
			if v, _ := bp.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if bp.options.redisLoader != nil {
		if lister, ok := bp.options.redisLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				bp.options.logger.Warnf("redis loader: %v", er)
			}
			patterns = append(patterns, list...)
		} else {
			r, er := bp.options.redisLoader.Load(ctx)
			if er != nil {
				bp.options.logger.Warnf("redis loader: %v", er)
			}
			if v, _ := bp.parsePatterns(r); v != nil {
				patterns = append(patterns, v...)
			}
		}
	}
	if bp.options.httpLoader != nil {
		r, er := bp.options.httpLoader.Load(ctx)
		if er != nil {
			bp.options.logger.Warnf("http loader: %v", er)
		}
		if v, _ := bp.parsePatterns(r); v != nil {
			patterns = append(patterns, v...)
		}
	}

	return
}

func (bp *localBypass) parsePatterns(r io.Reader) (patterns []string, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if line := bp.parseLine(scanner.Text()); line != "" {
			patterns = append(patterns, line)
		}
	}

	err = scanner.Err()
	return
}

func (bp *localBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if addr == "" || bp == nil {
		return false
	}

	matched := bp.matched(addr)

	b := !bp.options.whitelist && matched ||
		bp.options.whitelist && !matched
	if b {
		bp.options.logger.Debugf("bypass: %s, whitelist: %t", addr, bp.options.whitelist)
	} else {
		bp.options.logger.Debugf("pass: %s, whitelist: %t", addr, bp.options.whitelist)
	}
	return b
}

func (p *localBypass) IsWhitelist() bool {
	return p.options.whitelist
}

func (bp *localBypass) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

func (bp *localBypass) matched(addr string) bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	if bp.ipRangeMatcher.Match(addr) {
		return true
	}

	if bp.addrMatcher.Match(addr) {
		return true
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	if ip := net.ParseIP(host); ip != nil && bp.cidrMatcher.Match(host) {
		return true
	}

	return bp.wildcardMatcher.Match(addr)
}

func (bp *localBypass) Close() error {
	bp.cancelFunc()
	if bp.options.fileLoader != nil {
		bp.options.fileLoader.Close()
	}
	if bp.options.redisLoader != nil {
		bp.options.redisLoader.Close()
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
