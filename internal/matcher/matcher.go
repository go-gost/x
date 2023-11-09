package matcher

import (
	"fmt"
	"net"
	"strconv"
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

type addrMatcher struct {
	addrs map[string]*PortRange
}

// AddrMatcher creates a Matcher with a list of HOST:PORT addresses.
// the host can be an IP (e.g. 192.168.1.1) address, a plain domain such as 'example.com',
// or a special pattern '.example.com' that matches 'example.com'
// and any subdomain 'abc.example.com', 'def.abc.example.com' etc.
// The PORT can be a single port number or port range MIN-MAX(e.g. 0-65535).
func AddrMatcher(addrs []string) Matcher {
	matcher := &addrMatcher{
		addrs: make(map[string]*PortRange),
	}
	for _, addr := range addrs {
		host, port, _ := net.SplitHostPort(addr)
		if host == "" {
			matcher.addrs[addr] = nil
			continue
		}
		pr, _ := parsePortRange(port)
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
		if pr == nil || pr.contains(port) {
			return true
		}
	}

	if pr, ok := m.addrs["."+host]; ok {
		if pr == nil || pr.contains(port) {
			return true
		}
	}

	for {
		if index := strings.IndexByte(host, '.'); index > 0 {
			if pr, ok := m.addrs[host[index:]]; ok {
				if pr == nil || pr.contains(port) {
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
	pr   *PortRange
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
		pr, _ := parsePortRange(port)
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
		if pattern.glob.Match(addr) {
			if pattern.pr == nil || pattern.pr.contains(port) {
				return true
			}
		}
	}

	return false
}

type PortRange struct {
	Min int
	Max int
}

// ParsePortRange parses the s to a PortRange.
// The s can be a single port number and will be converted to port range port-port.
func parsePortRange(s string) (*PortRange, error) {
	minmax := strings.Split(s, "-")
	switch len(minmax) {
	case 1:
		port, err := strconv.Atoi(s)
		if err != nil {
			return nil, err
		}
		if port < 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", s)
		}
		return &PortRange{Min: port, Max: port}, nil

	case 2:
		min, err := strconv.Atoi(minmax[0])
		if err != nil {
			return nil, err
		}
		max, err := strconv.Atoi(minmax[1])
		if err != nil {
			return nil, err
		}

		return &PortRange{Min: min, Max: max}, nil

	default:
		return nil, fmt.Errorf("invalid range: %s", s)
	}
}

func (pr *PortRange) contains(port int) bool {
	return port >= pr.Min && port <= pr.Max
}
