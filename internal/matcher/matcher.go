package matcher

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	xnet "github.com/go-gost/x/internal/net"
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

type addrMatcher struct {
	addrs map[string]*xnet.PortRange
}

// AddrMatcher creates a Matcher with a list of HOST:PORT addresses.
// the host can be an IP (e.g. 192.168.1.1) address, a plain domain such as 'example.com',
// or a special pattern '.example.com' that matches 'example.com'
// and any subdomain 'abc.example.com', 'def.abc.example.com' etc.
// The PORT can be a single port number or port range MIN-MAX(e.g. 0-65535).
func AddrMatcher(addrs []string) Matcher {
	matcher := &addrMatcher{
		addrs: make(map[string]*xnet.PortRange),
	}
	for _, addr := range addrs {
		host, port, _ := net.SplitHostPort(addr)
		if host == "" {
			matcher.addrs[addr] = nil
			continue
		}
		pr := &xnet.PortRange{}
		if err := pr.Parse(port); err != nil {
			pr = nil
		}
		matcher.addrs[host] = pr
	}
	return matcher
}

func (m *addrMatcher) Match(addr string) bool {
	if m == nil || len(m.addrs) == 0 {
		return false
	}
	host, sp, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	port, _ := strconv.Atoi(sp)

	if pr, ok := m.addrs[host]; ok {
		if pr == nil || pr.Contains(port) {
			return true
		}
	}

	if pr, ok := m.addrs["."+host]; ok {
		if pr == nil || pr.Contains(port) {
			return true
		}
	}

	for {
		if index := strings.IndexByte(host, '.'); index > 0 {
			if pr, ok := m.addrs[host[index:]]; ok {
				if pr == nil || pr.Contains(port) {
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
	glob glob.Glob
	pr   *xnet.PortRange
}

type wildcardMatcher struct {
	patterns []wildcardMatcherPattern
}

// WildcardMatcher creates a Matcher for a specific wildcard domain pattern,
// the pattern can be a wildcard such as '*.exmaple.com', '*.example.com:80', or '*.example.com:0-65535'
func WildcardMatcher(patterns []string) Matcher {
	matcher := &wildcardMatcher{}
	for _, pattern := range patterns {
		host, port, _ := net.SplitHostPort(pattern)
		if host == "" {
			host = pattern
		}
		pr := &xnet.PortRange{}
		if err := pr.Parse(port); err != nil {
			pr = nil
		}

		matcher.patterns = append(matcher.patterns, wildcardMatcherPattern{
			glob: glob.MustCompile(host),
			pr:   pr,
		})
	}

	return matcher
}

func (m *wildcardMatcher) Match(addr string) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}

	host, sp, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
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

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
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
