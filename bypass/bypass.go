// Package bypass implements address-based routing that decides whether a
// target address should skip the proxy chain and connect directly.
//
// The package provides:
//   - NewBypass: a local bypass that matches addresses against CIDR, IP range,
//     wildcard, and exact-address patterns, with optional periodic reload from
//     file, Redis, or HTTP sources.
//   - BypassGroup: composes multiple bypass rules; whitelist rules use AND
//     logic, blacklist rules use OR logic (evaluated only if whitelist fails).
//   - Plugin-based bypass (gRPC and HTTP) in the plugin sub-package.
//
// Matching modes:
//   - Blacklist (whitelist=false): matching addresses bypass the proxy.
//     This is the default.
//   - Whitelist (whitelist=true):  only matching addresses bypass the proxy;
//     all other addresses go through the proxy chain.
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

// ErrBypass is returned by wrapped connections when the bypass rule
// determines that the connection should skip the proxy chain.
var ErrBypass = errors.New("bypass")

// options holds the configuration for a localBypass instance.
type options struct {
	// whitelist toggles between blacklist and whitelist mode.
	// When false (default): matching addresses bypass the proxy.
	// When true: only matching addresses bypass the proxy.
	whitelist bool

	// matchers holds static patterns provided at construction time
	// (e.g. from config file or command-line arguments).
	matchers []string

	// fileLoader loads patterns from a file or directory.
	fileLoader loader.Loader

	// redisLoader loads patterns from a Redis set or key.
	redisLoader loader.Loader

	// httpLoader loads patterns from an HTTP endpoint.
	httpLoader loader.Loader

	// period controls the interval between automatic reloads.
	// Values less than 1 second are clamped to 1 second.
	// A value <= 0 disables periodic reload (load once at startup).
	period time.Duration

	// logger is used for debug and warning messages.
	// Falls back to a no-op logger if nil.
	logger logger.Logger
}

// Option is a functional option for configuring a Bypass instance.
type Option func(opts *options)

// WhitelistOption sets whether the bypass operates in whitelist mode.
// In whitelist mode, only matching addresses bypass the proxy;
// all others go through the proxy chain.
func WhitelistOption(whitelist bool) Option {
	return func(opts *options) {
		opts.whitelist = whitelist
	}
}

// MatchersOption sets the static bypass patterns (CIDR, IP range, wildcard, or address).
func MatchersOption(matchers []string) Option {
	return func(opts *options) {
		opts.matchers = matchers
	}
}

// ReloadPeriodOption sets the interval between automatic reloads of bypass
// patterns from external loaders (file, Redis, HTTP).
func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

// FileLoaderOption sets the file loader for reading bypass patterns from a
// file or directory.
func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

// RedisLoaderOption sets the Redis loader for reading bypass patterns from a
// Redis set or key.
func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

// HTTPLoaderOption sets the HTTP loader for reading bypass patterns from an
// HTTP endpoint.
func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}

// LoggerOption sets the logger for debug and warning messages.
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

// localBypass is a Bypass that matches addresses against local pattern
// matchers. Patterns are classified into CIDR, wildcard, IP range, and
// exact address matchers. Patterns can be loaded from static config,
// file, Redis, or HTTP sources with optional periodic reload.
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

// NewBypass creates and initializes a local Bypass instance.
//
// In blacklist mode (the default), addresses matching any pattern bypass the
// proxy. In whitelist mode (set via WhitelistOption(true)), only matching
// addresses bypass the proxy and all others go through the chain.
//
// If a reload period is configured, patterns from external loaders are
// refreshed automatically in the background.
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

// periodReload loads patterns immediately, then periodically reloads them
// from external sources at the configured interval. Returns when ctx is
// cancelled.
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

// reload loads patterns from all configured sources, classifies them into
// CIDR, wildcard, IP range, and address matchers, then atomically swaps the
// matchers under the write lock.
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

// load reads patterns from file, Redis and HTTP loaders if configured.
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

// parsePatterns reads lines from r, strips comments and whitespace, and
// returns non-empty lines as patterns.
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

// parseLine removes comments (starting with '#') and trims whitespace.
func (p *localBypass) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

// matched checks whether addr matches any of the configured patterns.
// It tries IP range, address, CIDR, and wildcard matchers in order,
// returning true on the first match.
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
	if p.options.httpLoader != nil {
		p.options.httpLoader.Close()
	}
	return nil
}

// bypassGroup composes multiple Bypass instances into a single rule.
// Whitelist rules use AND logic (all must match); blacklist rules use
// OR logic (any match triggers bypass) and are only evaluated when
// whitelist rules fail.
type bypassGroup struct {
	bypasses []bypass.Bypass
}

// BypassGroup creates a composite Bypass from multiple rules.
// Whitelist rules use AND logic (all must match); blacklist rules use
// OR logic (any match triggers bypass) and are only evaluated when
// whitelist rules fail.
func BypassGroup(bypasses ...bypass.Bypass) bypass.Bypass {
	return &bypassGroup{
		bypasses: bypasses,
	}
}

// Contains evaluates all bypass rules in the group with the following logic:
//   - Whitelist rules: ALL must match (AND logic). If any whitelist rule
//     returns false, the combined whitelist result is false.
//   - Blacklist rules: only evaluated if the whitelist result is false.
//     ANY matching blacklist rule triggers a bypass (OR logic).
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

// IsWhitelist always returns false for a group, since the group may contain
// a mix of whitelist and blacklist rules.
func (p *bypassGroup) IsWhitelist() bool {
	return false
}
