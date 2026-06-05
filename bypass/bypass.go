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

	// network restricts this bypass to a specific network protocol.
	// When set, the incoming network must match before address matchers
	// are evaluated. Recognized values include "tcp" and "udp".
	// An empty value disables the network check.
	network string

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

// NetworkOption restricts this bypass to a specific network protocol.
// When set, Contains returns false when the incoming network does not
// match, regardless of address matchers. Accepts values like "tcp" or "udp".
func NetworkOption(network string) Option {
	return func(opts *options) {
		opts.network = network
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

// bypassDecision represents the outcome of evaluating a bypass rule.
type bypassDecision int

const (
	// decisionBypass means the address should connect directly, skipping the proxy chain.
	decisionBypass bypassDecision = iota
	// decisionProxy means the address should go through the proxy chain.
	decisionProxy
)

func (d bypassDecision) String() string {
	switch d {
	case decisionBypass:
		return "bypass"
	case decisionProxy:
		return "proxy"
	default:
		return "unknown"
	}
}

// patternSet holds classified pattern matchers for a single bypass rule.
// All four matcher types are built together by classifyPatterns and swapped
// atomically under the write lock.
type patternSet struct {
	cidr     matcher.Matcher
	addr     matcher.Matcher
	wildcard matcher.Matcher
	ipRange  matcher.Matcher
}

// matchAny reports whether addr matches any pattern in the set,
// trying IP range, address, CIDR, and wildcard matchers in order.
// Returns false if ps is nil.
func (ps *patternSet) matchAny(addr string) bool {
	if ps == nil {
		return false
	}
	if ps.ipRange.Match(addr) {
		return true
	}
	if ps.addr.Match(addr) {
		return true
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	if ip := net.ParseIP(host); ip != nil && ps.cidr.Match(host) {
		return true
	}

	return ps.wildcard.Match(addr)
}

// localBypass is a Bypass that matches addresses against local pattern
// matchers. Patterns are classified into CIDR, wildcard, IP range, and
// exact address matchers. Patterns can be loaded from static config,
// file, Redis, or HTTP sources with optional periodic reload.
type localBypass struct {
	patterns   *patternSet
	options    options
	logger     logger.Logger
	mu         sync.RWMutex
	cancelFunc context.CancelFunc
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
		cancelFunc: cancel,
		options:    options,
		logger:     options.logger,
	}
	if p.logger == nil {
		p.logger = xlogger.Nop()
	}

	if p.hasLoaders() {
		go p.periodReload(ctx)
	} else {
		_ = p.reload(ctx)
	}

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
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// reload loads patterns from all configured sources, classifies them into
// CIDR, wildcard, IP range, and address matchers, then atomically swaps the
// pattern set under the write lock.
func (p *localBypass) reload(ctx context.Context) error {
	v, err := p.load(ctx)
	if err != nil {
		return err
	}
	patterns := append(p.options.matchers, v...)
	p.logger.Debugf("load items %d", len(patterns))

	p.mu.Lock()
	if len(patterns) > 0 {
		p.patterns = classifyPatterns(patterns, p.logger)
	}
	p.mu.Unlock()

	return nil
}

// hasLoaders reports whether any external data source is configured,
// which determines whether a background reload goroutine is needed.
func (p *localBypass) hasLoaders() bool {
	return p.options.fileLoader != nil || p.options.redisLoader != nil || p.options.httpLoader != nil || p.options.period > 0
}

// classifyPatterns sorts raw pattern strings into typed matchers.
// Invalid wildcard patterns are logged and fall through to address matching.
func classifyPatterns(patterns []string, log logger.Logger) *patternSet {
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
			log.Warnf("invalid wildcard pattern %q, treating as plain address", pattern)
		}

		r := xnet.IPRange{}
		if err := r.Parse(pattern); err == nil {
			ipRanges = append(ipRanges, r)
			continue
		}

		addrs = append(addrs, pattern)
	}

	return &patternSet{
		cidr:     matcher.CIDRMatcher(inets),
		addr:     matcher.AddrMatcher(addrs),
		wildcard: matcher.WildcardMatcher(wildcards),
		ipRange:  matcher.IPRangeMatcher(ipRanges),
	}
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

	decision := p.decide(network, addr)

	log := p.logger.WithFields(map[string]any{
		"sid": ctxvalue.SidFromContext(ctx),
	})
	log.Debugf("%s: %s, whitelist: %t", decision, addr, p.options.whitelist)

	return decision == decisionBypass
}

// decide returns the bypass decision for the given address, applying the
// whitelist or blacklist mode to the pattern match result.
func (p *localBypass) decide(network string, addr string) bypassDecision {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.options.network != "" && p.options.network != network {
		return decisionProxy
	}

	if p.patterns == nil {
		if p.options.network != "" {
			if p.options.whitelist {
				return decisionProxy
			}
			return decisionBypass
		}

		return decisionProxy
	}

	matched := p.patterns.matchAny(addr)

	if p.options.whitelist {
		// Whitelist mode: the pattern set specifies addresses that MUST use the proxy.
		// Matched addresses go through the proxy; unmatched addresses bypass.
		if matched {
			return decisionProxy
		}
		return decisionBypass
	}
	// Blacklist mode: the pattern set specifies addresses that should bypass the proxy.
	// Matched addresses bypass; unmatched addresses go through the proxy.
	if matched {
		return decisionBypass
	}
	return decisionProxy
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
	return p.evaluate(ctx, network, addr, opts...) == decisionBypass
}

// evaluate returns the bypass decision for the group by applying two-phase
// evaluation: whitelist rules use AND logic (all must agree), then blacklist
// rules use OR logic (any match wins), evaluated only if whitelist fails.
func (p *bypassGroup) evaluate(ctx context.Context, network, addr string, opts ...bypass.Option) bypassDecision {
	// Phase 1: Whitelist AND — all must agree to bypass.
	hasWhitelist := false
	allWhitelistBypass := true
	for _, bp := range p.bypasses {
		if !bp.IsWhitelist() {
			continue
		}
		hasWhitelist = true
		if !bp.Contains(ctx, network, addr, opts...) {
			allWhitelistBypass = false
			break // short-circuit: one whitelist failure is enough
		}
	}
	if hasWhitelist && allWhitelistBypass {
		return decisionBypass
	}

	// Phase 2: Blacklist OR — any match triggers bypass.
	for _, bp := range p.bypasses {
		if bp.IsWhitelist() {
			continue
		}
		if bp.Contains(ctx, network, addr, opts...) {
			return decisionBypass
		}
	}
	return decisionProxy
}

// IsWhitelist always returns false for a group, since the group may contain
// a mix of whitelist and blacklist rules.
func (p *bypassGroup) IsWhitelist() bool {
	return false
}
