package routing

import (
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-gost/core/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsASCII(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"hello", true},
		{"Hello World 123!", true},
		{"/path/to/resource", true},
		{"café", false},
		{"日本語", false},
		{"\xff", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, IsASCII(tc.input))
		})
	}
}

func TestParseHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"example.com:8080", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:443", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"[fe80::1]:443", "fe80::1"},
		{"[::1]", "::1"},
		{"", ""},
		{":8080", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, parseHost(tc.input))
		})
	}
}

func TestMatcherClientIP(t *testing.T) {
	m, err := NewMatcher(`ClientIP("192.168.1.1")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		req  *routing.Request
		want bool
	}{
		{
			desc: "exact match",
			req:  &routing.Request{ClientIP: net.ParseIP("192.168.1.1")},
			want: true,
		},
		{
			desc: "no match",
			req:  &routing.Request{ClientIP: net.ParseIP("10.0.0.1")},
			want: false,
		},
		{
			desc: "nil ClientIP",
			req:  &routing.Request{ClientIP: nil},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.want, m.Match(tc.req))
		})
	}
}

func TestMatcherClientIP_CIDR(t *testing.T) {
	m, err := NewMatcher(`ClientIP("192.168.1.0/24")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		ip   string
		want bool
	}{
		{"in range", "192.168.1.50", true},
		{"network addr", "192.168.1.0", true},
		{"broadcast", "192.168.1.255", true},
		{"outside range", "192.168.2.1", false},
		{"different class", "10.0.0.1", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{ClientIP: net.ParseIP(tc.ip)}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherClientIP_Invalid(t *testing.T) {
	_, err := NewMatcher(`ClientIP("not-an-ip")`)
	assert.Error(t, err)
}

func TestMatcherProto(t *testing.T) {
	m, err := NewMatcher(`Proto("http")`)
	require.NoError(t, err)

	tests := []struct {
		desc    string
		proto   string
		want    bool
	}{
		{"lowercase match", "http", true},
		{"uppercase no match", "HTTP", false},
		{"wrong proto", "socks5", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Protocol: tc.proto}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherNetwork(t *testing.T) {
	m, err := NewMatcher(`Network("tcp")`)
	require.NoError(t, err)

	tests := []struct {
		desc    string
		network string
		want    bool
	}{
		{"exact match", "tcp", true},
		{"prefix match tcp4", "tcp4", true},
		{"prefix match tcp6", "tcp6", true},
		{"uppercase no match", "TCP", false},
		{"wrong network udp", "udp", false},
		{"wrong network udp4", "udp4", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Network: tc.network}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherMethod(t *testing.T) {
	m, err := NewMatcher(`Method("GET")`)
	require.NoError(t, err)

	tests := []struct {
		desc   string
		method string
		want   bool
	}{
		{"exact match", "GET", true},
		{"case mismatch", "get", false},
		{"wrong method", "POST", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Method: tc.method}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherPath(t *testing.T) {
	m, err := NewMatcher(`Path("/api/v1")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		path string
		want bool
	}{
		{"exact match", "/api/v1", true},
		{"prefix only", "/api/v1/users", false},
		{"no match", "/api/v2", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Path: tc.path}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherPath_NoLeadingSlash(t *testing.T) {
	_, err := NewMatcher(`Path("api")`)
	assert.Error(t, err)
}

func TestMatcherPathPrefix(t *testing.T) {
	m, err := NewMatcher(`PathPrefix("/api")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		path string
		want bool
	}{
		{"exact match", "/api", true},
		{"prefix match", "/api/v1/users", true},
		{"no match", "/other", false},
		{"partial no match", "/apifoo", true}, // HasPrefix matches this
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Path: tc.path}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherPathPrefix_NoLeadingSlash(t *testing.T) {
	_, err := NewMatcher(`PathPrefix("api")`)
	assert.Error(t, err)
}

func TestMatcherPathRegexp(t *testing.T) {
	m, err := NewMatcher(`PathRegexp("^/api/v[0-9]+")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		path string
		want bool
	}{
		{"match v1", "/api/v1/users", true},
		{"match v2", "/api/v2", true},
		{"no version", "/api/users", false},
		{"wrong path", "/other", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Path: tc.path}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherPathRegexp_Invalid(t *testing.T) {
	_, err := NewMatcher(`PathRegexp("[invalid")`)
	assert.Error(t, err)
}

func TestMatcherHost(t *testing.T) {
	m, err := NewMatcher(`Host("example.com")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		host string
		want bool
	}{
		{"exact match", "example.com", true},
		{"case insensitive", "EXAMPLE.COM", true},
		{"subdomain no match", "foo.example.com", false},
		{"with port", "example.com:8080", true},
		{"no match", "other.com", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Host: tc.host}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherHost_Wildcard(t *testing.T) {
	m, err := NewMatcher(`Host("*.example.com")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		host string
		want bool
	}{
		{"subdomain match", "foo.example.com", true},
		{"deep subdomain", "a.b.example.com", true},
		{"bare domain no match", "example.com", false},
		{"false suffix no match", "xexample.com", false},
		{"subdomain with port", "foo.example.com:8080", true},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Host: tc.host}
			assert.Equal(t, tc.want, m.Match(req), tc.desc)
		})
	}
}

func TestMatcherHost_NonASCII(t *testing.T) {
	_, err := NewMatcher(`Host("example.cóm")`)
	assert.Error(t, err)
}

func TestMatcherHostRegexp(t *testing.T) {
	m, err := NewMatcher(`HostRegexp(".*\\.example\\.com")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		host string
		want bool
	}{
		{"subdomain", "foo.example.com", true},
		{"bare domain", "example.com", false},
		{"no match", "other.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Host: tc.host}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherHostRegexp_Invalid(t *testing.T) {
	_, err := NewMatcher(`HostRegexp("[invalid")`)
	assert.Error(t, err)
}

func TestMatcherHostRegexp_NonASCII(t *testing.T) {
	_, err := NewMatcher(`HostRegexp("example.cóm")`)
	assert.Error(t, err)
}

func TestMatcherHeader(t *testing.T) {
	m, err := NewMatcher(`Header("X-Custom")`)
	require.NoError(t, err)

	tests := []struct {
		desc   string
		header http.Header
		want   bool
	}{
		{"present", http.Header{"X-Custom": {"value"}}, true},
		{"absent", http.Header{"Other": {"value"}}, false},
		{"nil header", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Header: tc.header}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherHeaderWithValue(t *testing.T) {
	m, err := NewMatcher(`Header("X-Custom", "secret")`)
	require.NoError(t, err)

	tests := []struct {
		desc   string
		header http.Header
		want   bool
	}{
		{"matching value", http.Header{"X-Custom": {"secret"}}, true},
		{"wrong value", http.Header{"X-Custom": {"other"}}, false},
		{"multiple values", http.Header{"X-Custom": {"other", "secret"}}, true},
		{"absent", http.Header{}, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Header: tc.header}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherHeaderRegexp(t *testing.T) {
	m, err := NewMatcher(`HeaderRegexp("X-Custom", "^v[0-9]+$")`)
	require.NoError(t, err)

	tests := []struct {
		desc   string
		header http.Header
		want   bool
	}{
		{"match v1", http.Header{"X-Custom": {"v1"}}, true},
		{"match v12", http.Header{"X-Custom": {"v12"}}, true},
		{"no match", http.Header{"X-Custom": {"invalid"}}, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Header: tc.header}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherHeaderRegexp_KeyOnly(t *testing.T) {
	// With 1 param, HeaderRegexp delegates to Header (key existence check)
	m, err := NewMatcher(`HeaderRegexp("X-Custom")`)
	require.NoError(t, err)

	req := &routing.Request{Header: http.Header{"X-Custom": {"anything"}}}
	assert.True(t, m.Match(req))

	req = &routing.Request{Header: http.Header{}}
	assert.False(t, m.Match(req))
}

func TestMatcherHeaderRegexp_Invalid(t *testing.T) {
	_, err := NewMatcher(`HeaderRegexp("X-Custom", "[invalid")`)
	assert.Error(t, err)
}

func TestMatcherQuery(t *testing.T) {
	m, err := NewMatcher(`Query("page")`)
	require.NoError(t, err)

	tests := []struct {
		desc  string
		query url.Values
		want  bool
	}{
		{"present", url.Values{"page": {"1"}}, true},
		{"absent", url.Values{"other": {"1"}}, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Query: tc.query}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherQueryWithValue(t *testing.T) {
	m, err := NewMatcher(`Query("page", "2")`)
	require.NoError(t, err)

	tests := []struct {
		desc  string
		query url.Values
		want  bool
	}{
		{"matching value", url.Values{"page": {"2"}}, true},
		{"wrong value", url.Values{"page": {"1"}}, false},
		{"multi-value", url.Values{"page": {"1", "2"}}, true},
		{"absent", url.Values{}, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Query: tc.query}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherQueryRegexp(t *testing.T) {
	m, err := NewMatcher(`QueryRegexp("page", "^[0-9]+$")`)
	require.NoError(t, err)

	tests := []struct {
		desc  string
		query url.Values
		want  bool
	}{
		{"numeric", url.Values{"page": {"42"}}, true},
		{"non-numeric", url.Values{"page": {"abc"}}, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Query: tc.query}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherQueryRegexp_KeyOnly(t *testing.T) {
	m, err := NewMatcher(`QueryRegexp("page")`)
	require.NoError(t, err)

	req := &routing.Request{Query: url.Values{"page": {"1"}}}
	assert.True(t, m.Match(req))

	req = &routing.Request{Query: url.Values{}}
	assert.False(t, m.Match(req))
}

func TestMatcherQueryRegexp_Invalid(t *testing.T) {
	_, err := NewMatcher(`QueryRegexp("page", "[invalid")`)
	assert.Error(t, err)
}

func TestMatcherBooleanAnd(t *testing.T) {
	m, err := NewMatcher(`Host("example.com") && Path("/api")`)
	require.NoError(t, err)

	req := &routing.Request{Host: "example.com", Path: "/api"}
	assert.True(t, m.Match(req))

	req = &routing.Request{Host: "example.com", Path: "/other"}
	assert.False(t, m.Match(req))

	req = &routing.Request{Host: "other.com", Path: "/api"}
	assert.False(t, m.Match(req))
}

func TestMatcherBooleanOr(t *testing.T) {
	m, err := NewMatcher(`Host("a.com") || Host("b.com")`)
	require.NoError(t, err)

	req := &routing.Request{Host: "a.com"}
	assert.True(t, m.Match(req))

	req = &routing.Request{Host: "b.com"}
	assert.True(t, m.Match(req))

	req = &routing.Request{Host: "c.com"}
	assert.False(t, m.Match(req))
}

func TestMatcherBooleanNot(t *testing.T) {
	m, err := NewMatcher(`!Host("example.com")`)
	require.NoError(t, err)

	req := &routing.Request{Host: "other.com"}
	assert.True(t, m.Match(req))

	req = &routing.Request{Host: "example.com"}
	assert.False(t, m.Match(req))
}

func TestMatcherBooleanComplex(t *testing.T) {
	// (Host a.com OR Host b.com) AND Path /api
	m, err := NewMatcher(`(Host("a.com") || Host("b.com")) && PathPrefix("/api")`)
	require.NoError(t, err)

	req := &routing.Request{Host: "a.com", Path: "/api/v1"}
	assert.True(t, m.Match(req))

	req = &routing.Request{Host: "c.com", Path: "/api/v1"}
	assert.False(t, m.Match(req))

	req = &routing.Request{Host: "a.com", Path: "/other"}
	assert.False(t, m.Match(req))
}

func TestMatcherBooleanDeMorgan(t *testing.T) {
	// !(Host a.com && Host b.com) => !Host a.com || !Host b.com
	m, err := NewMatcher(`!(Host("a.com") && Path("/secret"))`)
	require.NoError(t, err)

	// Both match → AND is true → NOT inverts to false
	req := &routing.Request{Host: "a.com", Path: "/secret"}
	assert.False(t, m.Match(req))

	// Only host matches → AND is false → NOT inverts to true
	req = &routing.Request{Host: "a.com", Path: "/public"}
	assert.True(t, m.Match(req))

	// Neither matches → AND is false → NOT inverts to true
	req = &routing.Request{Host: "b.com", Path: "/public"}
	assert.True(t, m.Match(req))
}

func TestMatcherInvalidRules(t *testing.T) {
	tests := []struct {
		desc string
		rule string
	}{
		{"empty", ""},
		{"unknown matcher", `Unknown("value")`},
		{"missing close paren", `Host("example.com"`},
		{"trailing and", `Host("a.com") &&`},
		{"trailing or", `Host("a.com") ||`},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewMatcher(tc.rule)
			assert.Error(t, err, "expected error for rule: %s", tc.rule)
		})
	}
}

func TestMatcherNilReceiver(t *testing.T) {
	var m *matcher
	assert.False(t, m.Match(&routing.Request{}))
}

func TestMatcherParameterCount(t *testing.T) {
	tests := []struct {
		desc string
		rule string
		ok   bool
	}{
		{"Host 0 params", `Host()`, false},
		{"Host 1 param", `Host("a.com")`, true},
		{"Host 2 params", `Host("a.com", "b.com")`, false},
		{"Header 1 param", `Header("X-Foo")`, true},
		{"Header 2 params", `Header("X-Foo", "bar")`, true},
		{"Header 3 params", `Header("X-Foo", "bar", "baz")`, false},
		{"Query 1 param", `Query("key")`, true},
		{"Query 2 params", `Query("key", "val")`, true},
		{"ClientIP 0 params", `ClientIP()`, false},
		{"Path 0 params", `Path()`, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewMatcher(tc.rule)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestMatcherCaseInsensitiveMatcherName(t *testing.T) {
	tests := []struct {
		desc string
		rule string
		host string
		want bool
	}{
		{"lowercase", `host("example.com")`, "example.com", true},
		{"uppercase", `HOST("example.com")`, "example.com", true},
		{"title case", `Host("example.com")`, "example.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			m, err := NewMatcher(tc.rule)
			require.NoError(t, err)
			req := &routing.Request{Host: tc.host}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherBodyRegexp(t *testing.T) {
	// Rule strings use the predicate parser (strconv.Unquote), so inner quotes
	// are escaped. In YAML config users write the equivalent backtick form:
	// BodyRegexp(`"model"\s*:\s*"gpt-4"`).
	m, err := NewMatcher(`BodyRegexp("\"model\"\\s*:\\s*\"gpt-4\"")`)
	require.NoError(t, err)

	tests := []struct {
		desc string
		body string
		want bool
	}{
		{"exact model", `{"model":"gpt-4"}`, true},
		{"spaced model", `{"model": "gpt-4", "max_tokens": 1}`, true},
		{"different model", `{"model":"claude"}`, false},
		{"empty body", ``, false},
		{"unrelated", `{"hello":"world"}`, false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &routing.Request{Body: []byte(tc.body)}
			assert.Equal(t, tc.want, m.Match(req))
		})
	}
}

func TestMatcherBodyRegexp_NilBody(t *testing.T) {
	m, err := NewMatcher(`BodyRegexp("foo")`)
	require.NoError(t, err)
	assert.False(t, m.Match(&routing.Request{}))
}

func TestMatcherBodyRegexp_Invalid(t *testing.T) {
	_, err := NewMatcher(`BodyRegexp("[invalid")`)
	assert.Error(t, err)
}

func TestMatcherBodyRegexp_CaseInsensitive(t *testing.T) {
	m, err := NewMatcher(`BodyRegexp("(?i)\"content-type\"\\s*:\\s*\"application/json\"")`)
	require.NoError(t, err)
	req := &routing.Request{Body: []byte(`{"Content-Type": "application/json"}`)}
	assert.True(t, m.Match(req))
}
