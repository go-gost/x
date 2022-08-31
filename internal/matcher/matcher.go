package matcher

import (
	"net"
	"strings"

	"github.com/gobwas/glob"
	"github.com/yl2chen/cidranger"
)

// Matcher is a generic pattern matcher,
// it gives the match result of the given pattern for specific v.
type Matcher interface {
	Match(v string) bool
}

type ipMatcher struct {
	ips map[string]struct{}
}

// IPMatcher creates a Matcher with a list of IP addresses.
func IPMatcher(ips []net.IP) Matcher {
	matcher := &ipMatcher{
		ips: make(map[string]struct{}),
	}
	for _, ip := range ips {
		matcher.ips[ip.String()] = struct{}{}
	}
	return matcher
}

func (m *ipMatcher) Match(ip string) bool {
	if m == nil || len(m.ips) == 0 {
		return false
	}
	_, ok := m.ips[ip]
	return ok
}

type cidrMatcher struct {
	ranger cidranger.Ranger
}

// CIDRMatcher creates a Matcher for a list of CIDR notation IP addresses.
func CIDRMatcher(inets []*net.IPNet) Matcher {
	ranger := cidranger.NewPCTrieRanger()
	for _, inet := range inets {
		ranger.Insert(cidranger.NewBasicRangerEntry(*inet))
	}
	return &cidrMatcher{ranger: ranger}
}

func (m *cidrMatcher) Match(ip string) bool {
	if m == nil || m.ranger == nil {
		return false
	}
	if netIP := net.ParseIP(ip); netIP != nil {
		b, _ := m.ranger.Contains(netIP)
		return b
	}
	return false
}

type domainMatcher struct {
	domains map[string]struct{}
}

// DomainMatcher creates a Matcher for a list of domains,
// the domain should be a plain domain such as 'example.com',
// or a special pattern '.example.com' that matches 'example.com'
// and any subdomain 'abc.example.com', 'def.abc.example.com' etc.
func DomainMatcher(domains []string) Matcher {
	matcher := &domainMatcher{
		domains: make(map[string]struct{}),
	}
	for _, domain := range domains {
		matcher.domains[domain] = struct{}{}
	}
	return matcher
}

func (m *domainMatcher) Match(domain string) bool {
	if m == nil || len(m.domains) == 0 {
		return false
	}

	if _, ok := m.domains[domain]; ok {
		return true
	}

	if _, ok := m.domains["."+domain]; ok {
		return true
	}

	for {
		if index := strings.IndexByte(domain, '.'); index > 0 {
			if _, ok := m.domains[domain[index:]]; ok {
				return true
			}
			domain = domain[index+1:]
			continue
		}
		break
	}
	return false
}

type wildcardMatcherPattern struct {
	pattern string
	glob    glob.Glob
}
type wildcardMatcher struct {
	patterns []wildcardMatcherPattern
}

// WildcardMatcher creates a Matcher for a specific wildcard domain pattern,
// the pattern should be a wildcard such as '*.exmaple.com'.
func WildcardMatcher(patterns []string) Matcher {
	matcher := &wildcardMatcher{}
	for _, pattern := range patterns {
		matcher.patterns = append(matcher.patterns, wildcardMatcherPattern{
			pattern: pattern,
			glob:    glob.MustCompile(pattern),
		})
	}

	return matcher
}

func (m *wildcardMatcher) Match(domain string) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}

	for _, pattern := range m.patterns {
		if pattern.glob.Match(domain) {
			return true
		}
	}

	return false
}
