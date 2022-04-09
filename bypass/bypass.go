package bypass

import (
	"net"
	"strings"

	bypass_pkg "github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/util/matcher"
)

type options struct {
	logger logger.Logger
}

type Option func(opts *options)

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type bypass struct {
	ipMatcher       matcher.Matcher
	cidrMatcher     matcher.Matcher
	domainMatcher   matcher.Matcher
	wildcardMatcher matcher.Matcher
	reversed        bool
	options         options
}

// NewBypassPatterns creates and initializes a new Bypass using matcher patterns as its match rules.
// The rules will be reversed if the reverse is true.
func NewBypass(reversed bool, patterns []string, opts ...Option) bypass_pkg.Bypass {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	var ips []net.IP
	var inets []*net.IPNet
	var domains []string
	var wildcards []string
	for _, pattern := range patterns {
		if ip := net.ParseIP(pattern); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if _, inet, err := net.ParseCIDR(pattern); err == nil {
			inets = append(inets, inet)
			continue
		}
		if strings.ContainsAny(pattern, "*?") {
			wildcards = append(wildcards, pattern)
			continue
		}
		domains = append(domains, pattern)

	}
	return &bypass{
		reversed:        reversed,
		options:         options,
		ipMatcher:       matcher.IPMatcher(ips),
		cidrMatcher:     matcher.CIDRMatcher(inets),
		domainMatcher:   matcher.DomainMatcher(domains),
		wildcardMatcher: matcher.WildcardMatcher(wildcards),
	}
}

func (bp *bypass) Contains(addr string) bool {
	if addr == "" || bp == nil {
		return false
	}

	// try to strip the port
	if host, _, _ := net.SplitHostPort(addr); host != "" {
		addr = host
	}

	matched := bp.matched(addr)

	b := !bp.reversed && matched ||
		bp.reversed && !matched
	if b {
		bp.options.logger.Debugf("bypass: %s", addr)
	}
	return b
}

func (bp *bypass) matched(addr string) bool {
	if ip := net.ParseIP(addr); ip != nil {
		return bp.ipMatcher.Match(addr) ||
			bp.cidrMatcher.Match(addr)
	}

	return bp.domainMatcher.Match(addr) ||
		bp.wildcardMatcher.Match(addr)
}
