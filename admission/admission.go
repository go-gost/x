package admission

import (
	"net"

	admission_pkg "github.com/go-gost/core/admission"
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

type admission struct {
	ipMatcher   matcher.Matcher
	cidrMatcher matcher.Matcher
	reversed    bool
	options     options
}

// NewAdmissionPatterns creates and initializes a new Admission using matcher patterns as its match rules.
// The rules will be reversed if the reverse is true.
func NewAdmission(reversed bool, patterns []string, opts ...Option) admission_pkg.Admission {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

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
	}
	return &admission{
		reversed:    reversed,
		options:     options,
		ipMatcher:   matcher.IPMatcher(ips),
		cidrMatcher: matcher.CIDRMatcher(inets),
	}
}

func (p *admission) Admit(addr string) bool {
	if addr == "" || p == nil {
		p.options.logger.Debugf("admission: %v is denied", addr)
		return false
	}

	// try to strip the port
	if host, _, _ := net.SplitHostPort(addr); host != "" {
		addr = host
	}

	matched := p.matched(addr)

	b := !p.reversed && matched ||
		p.reversed && !matched
	if !b {
		p.options.logger.Debugf("admission: %v is denied", addr)
	}
	return b
}

func (p *admission) matched(addr string) bool {
	return p.ipMatcher.Match(addr) ||
		p.cidrMatcher.Match(addr)
}
