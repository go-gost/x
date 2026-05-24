package matcher

import (
	"net"
	"testing"

	xnet "github.com/go-gost/x/internal/net"
)

// ---- IPMatcher ----

func TestIPMatcher_Match(t *testing.T) {
	m := IPMatcher([]net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
	})
	if !m.Match("192.168.1.1") {
		t.Error("expected match for 192.168.1.1")
	}
	if !m.Match("10.0.0.1") {
		t.Error("expected match for 10.0.0.1")
	}
	if m.Match("172.16.0.1") {
		t.Error("expected no match for 172.16.0.1")
	}
	if m.Match("") {
		t.Error("expected no match for empty string")
	}
}

func TestIPMatcher_EmptyIPs(t *testing.T) {
	m := IPMatcher(nil)
	if m.Match("192.168.1.1") {
		t.Error("expected no match when no IPs configured")
	}
}

func TestIPMatcher_NilMatcher(t *testing.T) {
	var m *ipMatcher
	if m.Match("192.168.1.1") {
		t.Error("expected no match on nil matcher")
	}
}

func TestIPMatcher_NormalizedIPv6(t *testing.T) {
	// Stored in compressed form, lookup with expanded form.
	m := IPMatcher([]net.IP{net.ParseIP("2001:db8::1")})
	if !m.Match("2001:db8:0:0:0:0:0:1") {
		t.Error("expected match for IPv6 expanded form")
	}
	if !m.Match("2001:db8::1") {
		t.Error("expected match for IPv6 compressed form")
	}
}

func TestIPMatcher_InvalidInput(t *testing.T) {
	m := IPMatcher([]net.IP{net.ParseIP("1.2.3.4")})
	if m.Match("not-an-ip") {
		t.Error("expected no match for invalid IP string")
	}
}

// ---- AddrMatcher ----

func TestAddrMatcher_ExactMatch(t *testing.T) {
	m := AddrMatcher([]string{"example.com:80", "192.168.1.1:443"})
	if !m.Match("example.com:80") {
		t.Error("expected match for example.com:80")
	}
	if !m.Match("192.168.1.1:443") {
		t.Error("expected match for 192.168.1.1:443")
	}
	if m.Match("example.com:443") {
		t.Error("expected no match for example.com:443")
	}
	if m.Match("other.com:80") {
		t.Error("expected no match for other.com:80")
	}
}

func TestAddrMatcher_PortRange(t *testing.T) {
	m := AddrMatcher([]string{"example.com:8000-9000"})
	if !m.Match("example.com:8000") {
		t.Error("expected match for port 8000 in range 8000-9000")
	}
	if !m.Match("example.com:9000") {
		t.Error("expected match for port 9000 in range 8000-9000")
	}
	if !m.Match("example.com:8500") {
		t.Error("expected match for port 8500 in range 8000-9000")
	}
	if m.Match("example.com:7999") {
		t.Error("expected no match for port 7999 outside 8000-9000")
	}
}

func TestAddrMatcher_NoPort(t *testing.T) {
	m := AddrMatcher([]string{"example.com"})
	if !m.Match("example.com:80") {
		t.Error("expected match for any port when no port configured")
	}
	if !m.Match("example.com:443") {
		t.Error("expected match for any port when no port configured")
	}
	if !m.Match("example.com") {
		t.Error("expected match when no port in input")
	}
}

func TestAddrMatcher_Subdomain(t *testing.T) {
	m := AddrMatcher([]string{".example.com:80"})
	if !m.Match("example.com:80") {
		t.Error("expected match for example.com:80 with .example.com rule")
	}
	if !m.Match("sub.example.com:80") {
		t.Error("expected match for sub.example.com:80 with .example.com rule")
	}
	if !m.Match("deep.sub.example.com:80") {
		t.Error("expected match for deep.sub.example.com:80 with .example.com rule")
	}
	if m.Match("other.com:80") {
		t.Error("expected no match for other.com:80")
	}
}

func TestAddrMatcher_MultiplePortsSameHost(t *testing.T) {
	m := AddrMatcher([]string{"example.com:80", "example.com:443"})
	if !m.Match("example.com:80") {
		t.Error("expected match for example.com:80 (first entry)")
	}
	if !m.Match("example.com:443") {
		t.Error("expected match for example.com:443 (second entry, should not overwrite first)")
	}
	if m.Match("example.com:8080") {
		t.Error("expected no match for example.com:8080")
	}
}

func TestAddrMatcher_CaseInsensitive(t *testing.T) {
	m := AddrMatcher([]string{"Example.COM:80"})
	if !m.Match("EXAMPLE.COM:80") {
		t.Error("expected case-insensitive match for EXAMPLE.COM:80")
	}
	if !m.Match("example.com:80") {
		t.Error("expected case-insensitive match for example.com:80")
	}
}

func TestAddrMatcher_CaseInsensitiveSubdomain(t *testing.T) {
	m := AddrMatcher([]string{".Example.COM:80"})
	if !m.Match("SUB.EXAMPLE.COM:80") {
		t.Error("expected case-insensitive subdomain match")
	}
	if !m.Match("sub.example.com:80") {
		t.Error("expected case-insensitive subdomain match (lowercased)")
	}
}

func TestAddrMatcher_EmptyAddrs(t *testing.T) {
	m := AddrMatcher(nil)
	if m.Match("example.com:80") {
		t.Error("expected no match when no addrs configured")
	}
}

func TestAddrMatcher_NilMatcher(t *testing.T) {
	var m *addrMatcher
	if m.Match("example.com:80") {
		t.Error("expected no match on nil matcher")
	}
}

func TestAddrMatcher_IPv6WithPort(t *testing.T) {
	m := AddrMatcher([]string{"[::1]:80"})
	if !m.Match("[::1]:80") {
		t.Error("expected match for [::1]:80")
	}
}

// ---- CIDRMatcher ----

func TestCIDRMatcher_Match(t *testing.T) {
	_, cidr1, _ := net.ParseCIDR("192.168.0.0/16")
	m := CIDRMatcher([]*net.IPNet{cidr1})
	if !m.Match("192.168.1.1") {
		t.Error("expected match for 192.168.1.1 in 192.168.0.0/16")
	}
	if !m.Match("192.168.255.255") {
		t.Error("expected match for 192.168.255.255 in 192.168.0.0/16")
	}
	if m.Match("10.0.0.1") {
		t.Error("expected no match for 10.0.0.1")
	}
	if m.Match("not-an-ip") {
		t.Error("expected no match for invalid IP")
	}
}

func TestCIDRMatcher_EmptyCIDRs(t *testing.T) {
	m := CIDRMatcher(nil)
	if m.Match("192.168.1.1") {
		t.Error("expected no match when no CIDRs configured")
	}
}

func TestCIDRMatcher_NilMatcher(t *testing.T) {
	var m *cidrMatcher
	if m.Match("192.168.1.1") {
		t.Error("expected no match on nil matcher")
	}
}

// ---- DomainMatcher ----

func TestDomainMatcher_ExactMatch(t *testing.T) {
	m := DomainMatcher([]string{"example.com", "test.org"})
	if !m.Match("example.com") {
		t.Error("expected match for example.com")
	}
	if !m.Match("test.org") {
		t.Error("expected match for test.org")
	}
	if m.Match("other.com") {
		t.Error("expected no match for other.com")
	}
}

func TestDomainMatcher_Subdomain(t *testing.T) {
	m := DomainMatcher([]string{".example.com"})
	if !m.Match("example.com") {
		t.Error("expected match for example.com with .example.com rule")
	}
	if !m.Match("sub.example.com") {
		t.Error("expected match for sub.example.com with .example.com rule")
	}
	if !m.Match("deep.sub.example.com") {
		t.Error("expected match for deep.sub.example.com")
	}
	if m.Match("notexample.com") {
		t.Error("expected no match for notexample.com (different domain)")
	}
}

func TestDomainMatcher_NestedSubdomain(t *testing.T) {
	m := DomainMatcher([]string{".example.com"})
	if !m.Match("a.b.c.example.com") {
		t.Error("expected match for deeply nested subdomain")
	}
}

func TestDomainMatcher_CaseInsensitive(t *testing.T) {
	m := DomainMatcher([]string{"Example.COM"})
	if !m.Match("EXAMPLE.COM") {
		t.Error("expected case-insensitive match for EXAMPLE.COM")
	}
	if !m.Match("example.com") {
		t.Error("expected case-insensitive match for example.com")
	}
}

func TestDomainMatcher_CaseInsensitiveSubdomain(t *testing.T) {
	m := DomainMatcher([]string{".Example.COM"})
	if !m.Match("SUB.EXAMPLE.COM") {
		t.Error("expected case-insensitive subdomain match")
	}
	if !m.Match("sub.example.com") {
		t.Error("expected case-insensitive subdomain match (lowercased)")
	}
}

func TestDomainMatcher_EmptyDomains(t *testing.T) {
	m := DomainMatcher(nil)
	if m.Match("example.com") {
		t.Error("expected no match when no domains configured")
	}
}

func TestDomainMatcher_NilMatcher(t *testing.T) {
	var m *domainMatcher
	if m.Match("example.com") {
		t.Error("expected no match on nil matcher")
	}
}

// ---- WildcardMatcher ----

func TestWildcardMatcher_Match(t *testing.T) {
	m := WildcardMatcher([]string{"*.example.com"})
	if !m.Match("foo.example.com") {
		t.Error("expected match for foo.example.com")
	}
	if !m.Match("bar.example.com") {
		t.Error("expected match for bar.example.com")
	}
	if m.Match("example.com") {
		t.Error("expected no match for example.com (no wildcard prefix)")
	}
	if m.Match("foo.other.com") {
		t.Error("expected no match for foo.other.com")
	}
}

func TestWildcardMatcher_WithPort(t *testing.T) {
	m := WildcardMatcher([]string{"*.example.com:443"})
	if !m.Match("foo.example.com:443") {
		t.Error("expected match for foo.example.com:443")
	}
	if m.Match("foo.example.com:80") {
		t.Error("expected no match for foo.example.com:80")
	}
}

func TestWildcardMatcher_WithPortRange(t *testing.T) {
	m := WildcardMatcher([]string{"*.example.com:8000-9000"})
	if !m.Match("foo.example.com:8000") {
		t.Error("expected match for port 8000")
	}
	if !m.Match("foo.example.com:8500") {
		t.Error("expected match for port 8500")
	}
	if m.Match("foo.example.com:7999") {
		t.Error("expected no match for port 7999")
	}
}

func TestWildcardMatcher_CaseInsensitive(t *testing.T) {
	m := WildcardMatcher([]string{"*.Example.COM"})
	if !m.Match("FOO.EXAMPLE.COM") {
		t.Error("expected case-insensitive match for FOO.EXAMPLE.COM")
	}
	if !m.Match("foo.example.com") {
		t.Error("expected case-insensitive match for foo.example.com")
	}
}

func TestWildcardMatcher_InvalidPattern(t *testing.T) {
	// MustCompile would panic on this; Compile should just skip it.
	m := WildcardMatcher([]string{"[invalid-glob"})
	if m.Match("anything") {
		t.Error("expected no match for invalid pattern")
	}
}

func TestWildcardMatcher_EmptyPatterns(t *testing.T) {
	m := WildcardMatcher(nil)
	if m.Match("foo.example.com") {
		t.Error("expected no match when no patterns configured")
	}
}

func TestWildcardMatcher_NilMatcher(t *testing.T) {
	var m *wildcardMatcher
	if m.Match("foo.example.com") {
		t.Error("expected no match on nil matcher")
	}
}

// ---- IPRangeMatcher ----

func TestIPRangeMatcher_Match(t *testing.T) {
	r := xnet.IPRange{}
	if err := r.Parse("192.168.1.1-192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	m := IPRangeMatcher([]xnet.IPRange{r})
	if !m.Match("192.168.1.1") {
		t.Error("expected match for 192.168.1.1 in range")
	}
	if !m.Match("192.168.1.5") {
		t.Error("expected match for 192.168.1.5 in range")
	}
	if !m.Match("192.168.1.10") {
		t.Error("expected match for 192.168.1.10 in range")
	}
	if m.Match("192.168.1.11") {
		t.Error("expected no match for 192.168.1.11")
	}
	if m.Match("10.0.0.1") {
		t.Error("expected no match for 10.0.0.1")
	}
}

func TestIPRangeMatcher_WithPort(t *testing.T) {
	r := xnet.IPRange{}
	if err := r.Parse("192.168.1.1-192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	m := IPRangeMatcher([]xnet.IPRange{r})
	if !m.Match("192.168.1.1:8080") {
		t.Error("expected match for 192.168.1.1:8080 (port stripped)")
	}
}

func TestIPRangeMatcher_EmptyRanges(t *testing.T) {
	m := IPRangeMatcher(nil)
	if m.Match("192.168.1.1") {
		t.Error("expected no match when no ranges configured")
	}
}

func TestIPRangeMatcher_NilMatcher(t *testing.T) {
	var m *ipRangeMatcher
	if m.Match("192.168.1.1") {
		t.Error("expected no match on nil matcher")
	}
}

// ---- NopMatcher ----

func TestNopMatcher_Match(t *testing.T) {
	m := NopMatcher()
	if m.Match("anything") {
		t.Error("nopMatcher should always return false")
	}
	if m.Match("") {
		t.Error("nopMatcher should always return false for empty string")
	}
}

func TestNopMatcher_NilMatcher(t *testing.T) {
	var m *nopMatcher
	if m.Match("anything") {
		t.Error("expected no match on nil matcher")
	}
}

// ---- Interface compliance ----

func TestMatcherInterface(t *testing.T) {
	// All constructors must return Matcher interface values.
	var _ Matcher = IPMatcher(nil)
	var _ Matcher = AddrMatcher(nil)
	var _ Matcher = CIDRMatcher(nil)
	var _ Matcher = DomainMatcher(nil)
	var _ Matcher = WildcardMatcher(nil)
	var _ Matcher = IPRangeMatcher(nil)
	var _ Matcher = NopMatcher()
}
