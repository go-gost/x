package matcher

import (
	"net"
	"strconv"
	"testing"

	xnet "github.com/go-gost/x/internal/net"
)

// ---------------------------------------------------------------------------
// IPMatcher
// ---------------------------------------------------------------------------

func BenchmarkIPMatcher(b *testing.B) {
	ips := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("::1"),
		net.ParseIP("2001:db8::1"),
	}
	m := IPMatcher(ips)

	b.Run("match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("192.168.1.1")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("172.16.0.1")
		}
	})
	b.Run("invalid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("not-an-ip")
		}
	})
}

func BenchmarkIPMatcher_Nil(b *testing.B) {
	var m *ipMatcher
	for i := 0; i < b.N; i++ {
		m.Match("192.168.1.1")
	}
}

// ---------------------------------------------------------------------------
// AddrMatcher
// ---------------------------------------------------------------------------

var benchAddrMatcher = AddrMatcher([]string{
	"example.com:80",
	"example.com:443",
	".example.com",
	"192.168.1.1:8080",
	"10.0.0.1",
	".sub.test.com:0-65535",
})

func BenchmarkAddrMatcher(b *testing.B) {
	b.Run("exact_host_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("example.com:80")
		}
	})
	b.Run("dot_prefix_subdomain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("api.example.com:443")
		}
	})
	b.Run("dot_prefix_exact", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("example.com:443")
		}
	})
	b.Run("ip_with_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("192.168.1.1:8080")
		}
	})
	b.Run("host_only", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("10.0.0.1")
		}
	})
	b.Run("deep_subdomain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("a.b.c.sub.test.com:1234")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchAddrMatcher.Match("other.com:80")
		}
	})
}

// ---------------------------------------------------------------------------
// CIDRMatcher
// ---------------------------------------------------------------------------

var benchCIDRMatcher = mustCIDRMatcher([]*net.IPNet{
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("2001:db8::/32"),
})

func BenchmarkCIDRMatcher(b *testing.B) {
	b.Run("match_v4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchCIDRMatcher.Match("192.168.100.50")
		}
	})
	b.Run("match_v6", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchCIDRMatcher.Match("2001:db8::42")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchCIDRMatcher.Match("8.8.8.8")
		}
	})
	b.Run("invalid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchCIDRMatcher.Match("not-an-ip")
		}
	})
}

// ---------------------------------------------------------------------------
// DomainMatcher
// ---------------------------------------------------------------------------

var benchDomainMatcher = DomainMatcher([]string{
	"example.com",
	".test.org",
	"sub.domain.io",
	".deep.sub.example.net",
})

func BenchmarkDomainMatcher(b *testing.B) {
	b.Run("exact", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchDomainMatcher.Match("example.com")
		}
	})
	b.Run("dot_prefix_subdomain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchDomainMatcher.Match("api.test.org")
		}
	})
	b.Run("dot_prefix_exact", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchDomainMatcher.Match("test.org")
		}
	})
	b.Run("deep_walk", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchDomainMatcher.Match("a.b.c.deep.sub.example.net")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchDomainMatcher.Match("other.com")
		}
	})
}

// ---------------------------------------------------------------------------
// WildcardMatcher
// ---------------------------------------------------------------------------

var benchWildcardMatcher = WildcardMatcher([]string{
	"*.example.com",
	"*.example.com:80",
	"*.test.org:0-65535",
	"mail.*.company.net",
})

func BenchmarkWildcardMatcher(b *testing.B) {
	b.Run("match_any_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchWildcardMatcher.Match("api.example.com:443")
		}
	})
	b.Run("match_specific_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchWildcardMatcher.Match("api.example.com:80")
		}
	})
	b.Run("match_range", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchWildcardMatcher.Match("sub.test.org:8080")
		}
	})
	b.Run("mid_wildcard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchWildcardMatcher.Match("mail.eu.company.net:25")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchWildcardMatcher.Match("other.com:80")
		}
	})
	b.Run("no_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchWildcardMatcher.Match("api.example.com")
		}
	})
}

// ---------------------------------------------------------------------------
// IPRangeMatcher
// ---------------------------------------------------------------------------

var benchIPRangeMatcher = IPRangeMatcher([]xnet.IPRange{
	mustIPRange("192.168.1.0", "192.168.1.255"),
	mustIPRange("10.0.0.0", "10.255.255.255"),
})

func BenchmarkIPRangeMatcher(b *testing.B) {
	b.Run("match_with_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchIPRangeMatcher.Match("192.168.1.100:8080")
		}
	})
	b.Run("match_no_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchIPRangeMatcher.Match("10.50.0.1")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchIPRangeMatcher.Match("172.16.0.1:80")
		}
	})
	b.Run("invalid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			benchIPRangeMatcher.Match("not-an-ip:80")
		}
	})
}

// ---------------------------------------------------------------------------
// NopMatcher
// ---------------------------------------------------------------------------

func BenchmarkNopMatcher(b *testing.B) {
	m := NopMatcher()
	for i := 0; i < b.N; i++ {
		m.Match("anything")
	}
}

// ---------------------------------------------------------------------------
// Large-scale AddrMatcher (many patterns)
// ---------------------------------------------------------------------------

func BenchmarkAddrMatcher_Large(b *testing.B) {
	addrs := make([]string, 500)
	for i := range addrs {
		addrs[i] = net.JoinHostPort(
			"host"+string(rune('a'+i%26))+".example.com",
			strconv.Itoa(i%65536),
		)
	}
	m := AddrMatcher(addrs)

	b.Run("first_match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("host0.example.com:0")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("unknown.host:80")
		}
	})
}

// ---------------------------------------------------------------------------
// Large-scale DomainMatcher (many patterns)
// ---------------------------------------------------------------------------

func BenchmarkDomainMatcher_Large(b *testing.B) {
	domains := make([]string, 1000)
	for i := range domains {
		domains[i] = "domain" + string(rune('a'+i%26)) + ".example.com"
	}
	m := DomainMatcher(domains)

	b.Run("match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("domaina.example.com")
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match("missing.example.com")
		}
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}

func mustCIDRMatcher(inets []*net.IPNet) Matcher {
	return CIDRMatcher(inets)
}

func mustIPRange(minStr, maxStr string) xnet.IPRange {
	r := xnet.IPRange{}
	if err := r.Parse(minStr + "-" + maxStr); err != nil {
		panic(err)
	}
	return r
}
