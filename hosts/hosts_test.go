package hosts

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
)

// newTestMapper creates a hostMapper for testing with a nop logger to avoid nil dereference
// when Lookup uses h.options.logger directly.
// It synchronously loads the initial mappings without starting the background reload goroutine
// to prevent data races between NewHostMapper's goroutine and test lookups.
func newTestMapper(opts ...Option) *hostMapper {
	opts = append(opts, LoggerOption(xlogger.Nop()))
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	ctx, cancel := context.WithCancel(context.TODO())
	h := &hostMapper{
		mappings:   make(map[string][]net.IP),
		cancelFunc: cancel,
		options:    options,
		logger:     options.logger,
	}
	if h.logger == nil {
		h.logger = xlogger.Nop()
	}
	_ = h.reload(ctx)
	cancel()
	return h
}

func TestParseLine(t *testing.T) {
	h := &hostMapper{}

	tests := []struct {
		name     string
		input    string
		expected []Mapping
	}{
		{
			name:  "single hostname",
			input: "127.0.0.1 localhost",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("127.0.0.1")},
			},
		},
		{
			name:  "multiple hostnames",
			input: "127.0.0.1 localhost loopback",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("127.0.0.1")},
				{Hostname: "loopback", IP: net.ParseIP("127.0.0.1")},
			},
		},
		{
			name:  "IPv6 address",
			input: "::1 localhost ipv6-localhost",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("::1")},
				{Hostname: "ipv6-localhost", IP: net.ParseIP("::1")},
			},
		},
		{
			name:     "comment with #",
			input:    "# this is a comment",
			expected: nil,
		},
		{
			name:  "inline comment",
			input: "127.0.0.1 localhost # loopback address",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("127.0.0.1")},
			},
		},
		{
			name:  "tab separated",
			input: "127.0.0.1\tlocalhost\tloopback",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("127.0.0.1")},
				{Hostname: "loopback", IP: net.ParseIP("127.0.0.1")},
			},
		},
		{
			name:  "mixed spaces and tabs",
			input: "127.0.0.1 \t localhost  \t loopback",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("127.0.0.1")},
				{Hostname: "loopback", IP: net.ParseIP("127.0.0.1")},
			},
		},
		{
			name:     "invalid IP address",
			input:    "not-an-ip hostname",
			expected: nil,
		},
		{
			name:     "empty line",
			input:    "",
			expected: nil,
		},
		{
			name:     "whitespace only line",
			input:    "   \t  ",
			expected: nil,
		},
		{
			name:     "IP only no hostname",
			input:    "127.0.0.1",
			expected: nil,
		},
		{
			name:     "comment only with whitespace",
			input:    "  # comment",
			expected: nil,
		},
		{
			name:  "extra whitespace between fields",
			input: "127.0.0.1    localhost     loopback",
			expected: []Mapping{
				{Hostname: "localhost", IP: net.ParseIP("127.0.0.1")},
				{Hostname: "loopback", IP: net.ParseIP("127.0.0.1")},
			},
		},
		{
			name:     "# only",
			input:    "#",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.parseLine(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d mappings, got %d", len(tt.expected), len(got))
			}
			for i := range got {
				if got[i].Hostname != tt.expected[i].Hostname {
					t.Errorf("mapping[%d] hostname: expected %q, got %q", i, tt.expected[i].Hostname, got[i].Hostname)
				}
				if !got[i].IP.Equal(tt.expected[i].IP) {
					t.Errorf("mapping[%d] IP: expected %s, got %s", i, tt.expected[i].IP, got[i].IP)
				}
			}
		})
	}
}

func TestParseMapping(t *testing.T) {
	h := &hostMapper{}

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "nil reader",
			input:    "",
			expected: 0,
		},
		{
			name:     "single line",
			input:    "127.0.0.1 localhost\n",
			expected: 1,
		},
		{
			name:     "multiple lines",
			input:    "127.0.0.1 localhost\n192.168.1.1 router\n",
			expected: 2,
		},
		{
			name:     "with comments and blanks",
			input:    "# comment\n127.0.0.1 localhost\n\n# another comment\n192.168.1.1 router\n",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r io.Reader
			if tt.input != "" {
				r = strings.NewReader(tt.input)
			}
			got, err := h.parseMapping(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.expected {
				t.Fatalf("expected %d mappings, got %d", tt.expected, len(got))
			}
		})
	}
}

func TestLookupExactMatch(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok {
		t.Fatal("expected lookup to succeed for 'example.com'")
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestLookupNoMatch(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
	}))

	_, ok := h.Lookup(context.Background(), "ip", "unknown.com")
	if ok {
		t.Fatal("expected lookup to fail for 'unknown.com'")
	}
}

func TestLookupDotPrefixWildcard(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: ".example.com", IP: net.ParseIP("10.0.0.1")},
	}))

	tests := []struct {
		host string
		ok   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			_, ok := h.Lookup(context.Background(), "ip", tt.host)
			if ok != tt.ok {
				t.Errorf("Lookup(%q) ok = %v, want %v", tt.host, ok, tt.ok)
			}
		})
	}
}

func TestLookupSubdomainWildcard(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: ".example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: ".foo.example.com", IP: net.ParseIP("10.0.0.2")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip", "foo.example.com")
	if !ok {
		t.Fatal("expected lookup to succeed for 'foo.example.com'")
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected [10.0.0.2], got %v", ips)
	}

	ips, ok = h.Lookup(context.Background(), "ip", "bar.example.com")
	if !ok {
		t.Fatal("expected lookup to succeed for 'bar.example.com'")
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestLookupIP4Filtering(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "dual.example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: "dual.example.com", IP: net.ParseIP("::1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip4", "dual.example.com")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestLookupIP6Filtering(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "dual.example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: "dual.example.com", IP: net.ParseIP("::1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip6", "dual.example.com")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("expected [::1], got %v", ips)
	}
}

func TestLookupDefaultNetwork(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: "example.com", IP: net.ParseIP("::1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs with 'ip' network, got %d", len(ips))
	}
}

func TestLookupEmptyMappings(t *testing.T) {
	h := newTestMapper()

	_, ok := h.Lookup(context.Background(), "ip", "example.com")
	if ok {
		t.Fatal("expected lookup to fail with empty mappings")
	}
}

func TestReload(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatal("initial mapping not found")
	}

	h.options.mappings = []Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.2")},
	}
	_ = h.reload(context.Background())

	ips, ok = h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected [10.0.0.2] after reload, got %v", ips)
	}
}

func TestReloadDedupIPs(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 deduplicated IP, got %d", len(ips))
	}
}

func TestClose(t *testing.T) {
	h := NewHostMapper().(*hostMapper)
	err := h.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	err = h.Close()
	if err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

type testLoader struct {
	data string
}

func (l *testLoader) Load(_ context.Context) (io.Reader, error) {
	return strings.NewReader(l.data), nil
}

func (l *testLoader) Close() error { return nil }

func TestLoadFileLoader(t *testing.T) {
	h := newTestMapper(
		FileLoaderOption(&testLoader{data: "10.0.0.1 example.com\n"}),
	)

	_ = h.reload(context.Background())

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestLoadHTTPLoader(t *testing.T) {
	h := newTestMapper(
		HTTPLoaderOption(&testLoader{data: "10.0.0.1 example.com\n"}),
	)

	_ = h.reload(context.Background())

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestLoadRedisLoader(t *testing.T) {
	h := newTestMapper(
		RedisLoaderOption(&testLoader{data: "10.0.0.1 example.com\n"}),
	)

	_ = h.reload(context.Background())

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

type testLister struct {
	lines []string
}

func (l *testLister) Load(_ context.Context) (io.Reader, error) {
	return nil, nil
}

func (l *testLister) List(_ context.Context) ([]string, error) {
	return l.lines, nil
}

func (l *testLister) Close() error { return nil }

func TestLoadFileLoaderAsLister(t *testing.T) {
	h := newTestMapper(
		FileLoaderOption(&testLister{lines: []string{"10.0.0.1 example.com", "192.168.1.1 router"}}),
	)

	_ = h.reload(context.Background())

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}

	ips, ok = h.Lookup(context.Background(), "ip", "router")
	if !ok || !ips[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("expected [192.168.1.1], got %v", ips)
	}
}

func TestLoadRedisLoaderAsLister(t *testing.T) {
	h := newTestMapper(
		RedisLoaderOption(&testLister{lines: []string{"10.0.0.1 example.com"}}),
	)

	_ = h.reload(context.Background())

	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestCloseClosesLoaders(t *testing.T) {
	cl := &closeTrackingLoader{}
	h := newTestMapper(
		FileLoaderOption(cl),
		RedisLoaderOption(cl),
		HTTPLoaderOption(cl),
	)

	_ = h.Close()

	if cl.count != 3 {
		t.Fatalf("expected Close called 3 times, got %d", cl.count)
	}
}

type closeTrackingLoader struct {
	count int
}

func (l *closeTrackingLoader) Load(_ context.Context) (io.Reader, error) {
	return strings.NewReader(""), nil
}

func (l *closeTrackingLoader) Close() error {
	l.count++
	return nil
}

func TestReloadPeriodOption(t *testing.T) {
	period := 5 * time.Minute
	h := newTestMapper(ReloadPeriodOption(period))
	if h.options.period != period {
		t.Fatalf("expected period %v, got %v", period, h.options.period)
	}
}

func TestLoggerOption(t *testing.T) {
	h := NewHostMapper().(*hostMapper)
	if h.logger == nil {
		t.Fatal("expected non-nil default logger")
	}
}

func TestLookupContextCancellation(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("10.0.0.1")},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ips, ok := h.Lookup(ctx, "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v (ok=%v)", ips, ok)
	}
}

func TestPeriodReloadNegativePeriod(t *testing.T) {
	h := NewHostMapper(
		ReloadPeriodOption(-1*time.Second),
		LoggerOption(xlogger.Nop()),
	).(*hostMapper)

	err := h.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestSubdomainWildcardDeeperMatch(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: ".example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: ".b.example.com", IP: net.ParseIP("10.0.0.2")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip", "a.b.example.com")
	if !ok {
		t.Fatal("expected lookup to succeed for 'a.b.example.com'")
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected [10.0.0.2] (more specific), got %v", ips)
	}

	ips, ok = h.Lookup(context.Background(), "ip", "c.example.com")
	if !ok {
		t.Fatal("expected lookup to succeed for 'c.example.com'")
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestLookupIPv4MappedIPv6(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: "example.com", IP: net.ParseIP("::ffff:10.0.0.1")},
	}))

	ips, ok := h.Lookup(context.Background(), "ip4", "example.com")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1] (unwrapped IPv4), got %v", ips)
	}

	ips, ok = h.Lookup(context.Background(), "ip6", "example.com")
	if ok || len(ips) != 0 {
		t.Fatalf("expected no results for ip6 filter, got %v (ok=%v)", ips, ok)
	}
}

func TestLookupCatchAll(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: ".", IP: net.ParseIP("10.0.0.1")},
	}))
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		ok   bool
	}{
		{"example.com", true},
		{"anything.else.com", true},
		{"deep.sub.domain.org", true},
		{"singleword", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			_, ok := h.Lookup(context.Background(), "ip", tt.host)
			if ok != tt.ok {
				t.Errorf("Lookup(%q) ok = %v, want %v", tt.host, ok, tt.ok)
			}
		})
	}
}

func TestLookupCatchAllWithSpecific(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: ".example.com", IP: net.ParseIP("10.0.0.1")},
		{Hostname: ".", IP: net.ParseIP("10.0.0.2")},
	}))
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	// Specific .suffix should take priority over catch-all
	ips, ok := h.Lookup(context.Background(), "ip", "example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1] from .example.com, got %v (ok=%v)", ips, ok)
	}

	ips, ok = h.Lookup(context.Background(), "ip", "sub.example.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1] from .example.com, got %v (ok=%v)", ips, ok)
	}

	// Unmatched hostname falls through to catch-all
	ips, ok = h.Lookup(context.Background(), "ip", "other.com")
	if !ok || !ips[0].Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected [10.0.0.2] from catch-all, got %v (ok=%v)", ips, ok)
	}
}

func TestLookupCatchAllIP4IP6(t *testing.T) {
	h := newTestMapper(MappingsOption([]Mapping{
		{Hostname: ".", IP: net.ParseIP("10.0.0.1")},
		{Hostname: ".", IP: net.ParseIP("::1")},
	}))
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	ips, ok := h.Lookup(context.Background(), "ip4", "anyhost.com")
	if !ok || len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected [10.0.0.1] via ip4 catch-all, got %v (ok=%v)", ips, ok)
	}

	ips, ok = h.Lookup(context.Background(), "ip6", "anyhost.com")
	if !ok || len(ips) != 1 || !ips[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("expected [::1] via ip6 catch-all, got %v (ok=%v)", ips, ok)
	}

	ips, ok = h.Lookup(context.Background(), "ip", "anyhost.com")
	if !ok || len(ips) != 2 {
		t.Fatalf("expected 2 IPs via catch-all, got %d (ok=%v)", len(ips), ok)
	}
}

func TestLoaderWithListerPattern(t *testing.T) {
	var _ loader.Loader = (*testLister)(nil)
	var _ loader.Lister = (*testLister)(nil)

	var _ loader.Loader = (*testLoader)(nil)
	_, isLister := interface{}(&testLoader{}).(loader.Lister)
	if isLister {
		t.Fatal("testLoader should not implement Lister")
	}
}
