// Package matcher provides pattern matching utilities for IP addresses,
// CIDR blocks, domains, wildcard patterns, and address:port combinations.
package matcher

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	xnet "github.com/go-gost/x/internal/net"
	"github.com/gobwas/glob"
)

// Matcher is a generic pattern matcher that tests whether a given value
// matches any of the pre-configured patterns.
type Matcher interface {
	Match(v string) bool
}

// splitHostPort splits addr into host and port without allocating when
// addr contains no colon (i.e. no port). For inputs with a colon,
// net.SplitHostPort is used as normal.
func splitHostPort(addr string) (host, port string) {
	if !strings.Contains(addr, ":") {
		return addr, ""
	}
	host, port, _ = net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	return
}

type ipMatcher struct {
	ips map[netip.Addr]struct{}
}

// IPMatcher creates a Matcher for a list of IP addresses.
func IPMatcher(ips []net.IP) Matcher {
	matcher := &ipMatcher{
		ips: make(map[netip.Addr]struct{}),
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		matcher.ips[addr.Unmap()] = struct{}{}
	}
	return matcher
}

func (m *ipMatcher) Match(ip string) bool {
	if m == nil || len(m.ips) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	_, ok := m.ips[addr.Unmap()]
	return ok
}

type addrMatcher struct {
	addrs map[string][]*xnet.PortRange
}

// AddrMatcher creates a Matcher for a list of HOST:PORT addresses.
// The host can be an IP address (e.g. 192.168.1.1), a plain domain such as
// "example.com", or a special pattern ".example.com" that matches
// "example.com" and any subdomain "abc.example.com", "def.abc.example.com"
// etc. The PORT can be a single port number or port range MIN-MAX
// (e.g. 0-65535).
func AddrMatcher(addrs []string) Matcher {
	matcher := &addrMatcher{
		addrs: make(map[string][]*xnet.PortRange),
	}
	for _, addr := range addrs {
		host, port := splitHostPort(addr)
		if host == "" {
			host = strings.ToLower(addr)
			matcher.addrs[host] = append(matcher.addrs[host], nil)
			continue
		}
		host = strings.ToLower(host)
		pr := &xnet.PortRange{}
		if err := pr.Parse(port); err != nil {
			pr = nil
		}
		matcher.addrs[host] = append(matcher.addrs[host], pr)
	}
	return matcher
}

func (m *addrMatcher) Match(addr string) bool {
	if m == nil || len(m.addrs) == 0 {
		return false
	}
	host, sp := splitHostPort(addr)
	host = strings.ToLower(host)
	port, _ := strconv.Atoi(sp)

	if prs, ok := m.addrs[host]; ok {
		if portRangeMatch(prs, port) {
			return true
		}
	}

	if prs, ok := m.addrs["."+host]; ok {
		if portRangeMatch(prs, port) {
			return true
		}
	}

	for {
		if index := strings.IndexByte(host, '.'); index > 0 {
			if prs, ok := m.addrs[host[index:]]; ok {
				if portRangeMatch(prs, port) {
					return true
				}
			}
			host = host[index+1:]
			continue
		}
		break
	}

	return false
}

// portRangeMatch returns true if any PortRange in prs contains port.
// A nil entry means "any port" and always matches.
func portRangeMatch(prs []*xnet.PortRange, port int) bool {
	for _, pr := range prs {
		if pr == nil || pr.Contains(port) {
			return true
		}
	}
	return false
}

type cidrMatcher struct {
	trie *cidrTrie
}

// CIDRMatcher creates a Matcher for a list of CIDR notation IP addresses.
func CIDRMatcher(inets []*net.IPNet) Matcher {
	trie := newCIDRTrie()
	for _, inet := range inets {
		if prefix, ok := ipNetToPrefix(inet); ok {
			trie.insert(prefix)
		}
	}
	return &cidrMatcher{trie: trie}
}

func (m *cidrMatcher) Match(ip string) bool {
	if m == nil || m.trie == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return m.trie.contains(addr.Unmap())
}

type domainMatcher struct {
	domains map[string]struct{}
}

// DomainMatcher creates a Matcher for a list of domains.
// The domain should be a plain domain such as "example.com",
// or a special pattern ".example.com" that matches "example.com"
// and any subdomain "abc.example.com", "def.abc.example.com" etc.
func DomainMatcher(domains []string) Matcher {
	matcher := &domainMatcher{
		domains: make(map[string]struct{}),
	}
	for _, domain := range domains {
		matcher.domains[strings.ToLower(domain)] = struct{}{}
	}
	return matcher
}

func (m *domainMatcher) Match(domain string) bool {
	if m == nil || len(m.domains) == 0 {
		return false
	}

	domain = strings.ToLower(domain)

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
	glob glob.Glob
	pr   *xnet.PortRange
}

type wildcardMatcher struct {
	patterns []wildcardMatcherPattern
}

// WildcardMatcher creates a Matcher for wildcard domain patterns.
// The pattern can be a wildcard such as "*.example.com",
// "*.example.com:80", or "*.example.com:0-65535".
func WildcardMatcher(patterns []string) Matcher {
	matcher := &wildcardMatcher{}
	for _, pattern := range patterns {
		host, port := splitHostPort(pattern)
		if host == "" {
			host = pattern
		}
		g, err := glob.Compile(strings.ToLower(host))
		if err != nil {
			continue
		}
		pr := &xnet.PortRange{}
		if err := pr.Parse(port); err != nil {
			pr = nil
		}

		matcher.patterns = append(matcher.patterns, wildcardMatcherPattern{
			glob: g,
			pr:   pr,
		})
	}

	return matcher
}

func (m *wildcardMatcher) Match(addr string) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}

	host, sp := splitHostPort(addr)
	host = strings.ToLower(host)
	port, _ := strconv.Atoi(sp)
	for _, pattern := range m.patterns {
		if pattern.glob.Match(host) {
			if pattern.pr == nil || pattern.pr.Contains(port) {
				return true
			}
		}
	}

	return false
}

type ipRangeMatcher struct {
	ranges []xnet.IPRange
}

// IPRangeMatcher creates a Matcher for a list of IP ranges (e.g. "192.168.1.1-192.168.1.255").
func IPRangeMatcher(ranges []xnet.IPRange) Matcher {
	matcher := &ipRangeMatcher{
		ranges: ranges,
	}
	return matcher
}

func (m *ipRangeMatcher) Match(addr string) bool {
	if m == nil || len(m.ranges) == 0 {
		return false
	}

	host, _ := splitHostPort(addr)
	adr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	for _, ra := range m.ranges {
		if ra.Contains(adr) {
			return true
		}
	}
	return false
}

type nopMatcher struct{}

// NopMatcher creates a Matcher that never matches anything.
func NopMatcher() Matcher {
	return &nopMatcher{}
}

func (m *nopMatcher) Match(addr string) bool {
	return false
}
