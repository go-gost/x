// Package admission implements access control for incoming connections.
// Before a connection is handled, the admission controller checks whether
// the client's address is allowed to use the service.
//
// The package provides:
//   - NewAdmission: a local admission controller backed by IP/CIDR matchers,
//     with optional periodic reload from file, Redis, or HTTP sources.
//   - AdmissionGroup: composes multiple admission controllers; all must
//     admit for the connection to proceed.
//   - Plugin-based admission (gRPC and HTTP) in the plugin sub-package.
//   - Connection wrappers in the wrapper sub-package that enforce
//     admission checks per-read (for TCP) and per-packet (for UDP).
//
// Matching modes:
//   - Whitelist (whitelist=true):  only addresses matching a rule are admitted.
//   - Blacklist (whitelist=false): addresses matching a rule are denied;
//     everything else is admitted. This is the default.
package admission

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/matcher"
	xlogger "github.com/go-gost/x/logger"
)

// options holds the configuration for a localAdmission instance.
type options struct {
	// whitelist toggles between blacklist and whitelist mode.
	// When false (default): matching addresses are denied.
	// When true: only matching addresses are allowed.
	whitelist bool

	// matchers holds static patterns provided at construction time
	// (e.g. from config file or command-line arguments).
	matchers []string

	// fileLoader loads patterns from a file or directory.
	// Supports hot-reload via file watching if the loader implements Lister.
	fileLoader loader.Loader

	// redisLoader loads patterns from a Redis set or key.
	// Supports hot-reload via periodic polling if the loader implements Lister.
	redisLoader loader.Loader

	// httpLoader loads patterns from an HTTP endpoint.
	// Supports hot-reload via periodic polling.
	httpLoader loader.Loader

	// period controls the interval between automatic reloads.
	// Values less than 1 second are clamped to 1 second.
	// A value <= 0 disables periodic reload (load once at startup).
	period time.Duration

	// logger is used for debug and warning messages.
	// Falls back to a no-op logger if nil.
	logger logger.Logger
}

// Option is a functional option for configuring an admission controller.
type Option func(opts *options)

// WhitelistOption sets whether the admission controller operates in
// whitelist mode. In whitelist mode, only addresses matching one or more
// rules are admitted; all others are denied.
func WhitelistOption(whitelist bool) Option {
	return func(opts *options) {
		opts.whitelist = whitelist
	}
}

// MatchersOption sets static match patterns that are combined with
// dynamically loaded patterns on each reload. Patterns may be:
//   - Bare IP addresses: "192.168.1.1", "::1"
//   - CIDR networks: "10.0.0.0/8", "fd00::/8"
//   - Hostnames: resolved to IP addresses via DNS
func MatchersOption(matchers []string) Option {
	return func(opts *options) {
		opts.matchers = matchers
	}
}

// ReloadPeriodOption sets the interval for automatically reloading
// patterns from external loaders (file, Redis, HTTP). A value <= 0
// disables periodic reloading.
func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

// FileLoaderOption sets the file-based pattern loader.
func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

// RedisLoaderOption sets the Redis-based pattern loader.
func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

// HTTPLoaderOption sets the HTTP-based pattern loader.
func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}

// LoggerOption sets the logger for the admission controller.
func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

// localAdmission is the in-process admission controller. It maintains
// two matchers — one for individual IP addresses and one for CIDR
// networks — and checks incoming addresses against them.
//
// The matchers are rebuilt atomically on each reload: new patterns
// are loaded, parsed into IPs and CIDRs, and the matchers are swapped
// under a write lock.
type localAdmission struct {
	ipMatcher   matcher.Matcher // matches individual IP addresses
	cidrMatcher matcher.Matcher // matches CIDR network ranges
	mu          sync.RWMutex    // protects ipMatcher and cidrMatcher
	cancelFunc  context.CancelFunc
	options     options
	logger      logger.Logger
}

// NewAdmission creates a local admission controller with the given options.
// It starts a background goroutine that periodically reloads patterns
// from configured external sources (file, Redis, HTTP).
//
// By default the controller operates in blacklist mode: any address
// matching the loaded patterns is denied. Use WhitelistOption(true)
// to invert this.
func NewAdmission(opts ...Option) admission.Admission {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &localAdmission{
		ipMatcher:   matcher.NopMatcher(),
		cidrMatcher: matcher.NopMatcher(),
		cancelFunc:  cancel,
		options:     options,
		logger:      options.logger,
	}
	if p.logger == nil {
		p.logger = xlogger.Nop()
	}

	go p.periodReload(ctx)

	return p
}

// Admit decides whether the given network address is allowed.
// It returns true if the address should be accepted, false otherwise.
//
// The address is first stripped of its port (if present), then matched
// against the IP and CIDR matchers. The whitelist/blacklist mode
// determines how the match result is interpreted:
//
//	Blacklist (whitelist=false): admit if NOT matched
//	Whitelist (whitelist=true):  admit only if matched
//
// An empty address or a nil receiver always returns true.
func (p *localAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	if addr == "" || p == nil {
		return true
	}

	// try to strip the port
	if host, _, _ := net.SplitHostPort(addr); host != "" {
		addr = host
	}

	matched := p.matched(addr)

	b := !p.options.whitelist && !matched ||
		p.options.whitelist && matched

	if !b {
		p.logger.Debugf("%s is denied", addr)
	}
	return b
}

// periodReload triggers an immediate reload, then — if a positive period
// is configured — reloads on each tick. It exits when ctx is cancelled.
func (p *localAdmission) periodReload(ctx context.Context) error {
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

// reload loads patterns from all configured sources, parses them into
// IP addresses and CIDR networks, and atomically swaps the matchers.
func (p *localAdmission) reload(ctx context.Context) error {
	v, err := p.load(ctx)
	if err != nil {
		return err
	}
	patterns := append(p.options.matchers, v...)

	var ips []net.IP
	var inets []*net.IPNet
	for _, pattern := range patterns {
		if ip := net.ParseIP(pattern); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if _, inet, err := net.ParseCIDR(pattern); err == nil {
			inets = append(inets, inet)
			continue
		}
		// Try DNS resolution as a last resort.
		if ipAddr, _ := net.ResolveIPAddr("ip", pattern); ipAddr != nil {
			p.logger.Debugf("resolve IP: %s -> %s", pattern, ipAddr)
			ips = append(ips, ipAddr.IP)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.ipMatcher = matcher.IPMatcher(ips)
	p.cidrMatcher = matcher.CIDRMatcher(inets)

	return nil
}

// load collects patterns from all configured external loaders
// (file, Redis, HTTP). It prefers the Lister interface when available,
// falling back to loading raw content via Load and parsing line-by-line.
func (p *localAdmission) load(ctx context.Context) (patterns []string, err error) {
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

	p.logger.Debugf("load items %d", len(patterns))
	return
}

// parsePatterns reads a newline-delimited stream and returns a list of
// non-empty, trimmed lines after stripping comments.
func (p *localAdmission) parsePatterns(r io.Reader) (patterns []string, err error) {
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

// parseLine strips inline comments (everything after the first '#')
// and trims surrounding whitespace. It returns an empty string if
// the line was a comment-only or blank line.
func (p *localAdmission) parseLine(s string) string {
	if n := strings.IndexByte(s, '#'); n >= 0 {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

// matched returns true if addr is matched by either the IP or CIDR
// matcher. Caller must hold at least a read lock.
func (p *localAdmission) matched(addr string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.ipMatcher.Match(addr) ||
		p.cidrMatcher.Match(addr)
}

// Close stops the background reload goroutine and closes all external
// loaders. It is safe to call after the admission controller is no
// longer needed.
func (p *localAdmission) Close() error {
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

// admissionGroup composes multiple admission controllers into one.
// All controllers in the group must admit for the overall result to
// be true (logical AND).
type admissionGroup struct {
	admissions []admission.Admission
}

// AdmissionGroup creates a composite admission controller that requires
// every member to admit the address. If any member denies, the address
// is denied immediately (short-circuit evaluation).
//
// Nil members are skipped.
func AdmissionGroup(admissions ...admission.Admission) admission.Admission {
	return &admissionGroup{
		admissions: admissions,
	}
}

func (p *admissionGroup) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	for _, admission := range p.admissions {
		if admission != nil && !admission.Admit(ctx, network, addr, opts...) {
			return false
		}
	}
	return true
}
