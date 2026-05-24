package ingress

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
)

// newTestIngress creates a localIngress for testing with a nop logger
// and synchronously loads initial rules to avoid races with the background
// reload goroutine started by NewIngress.
func newTestIngress(opts ...Option) *localIngress {
	opts = append(opts, LoggerOption(xlogger.Nop()))
	ing := NewIngress(opts...).(*localIngress)
	_ = ing.reload(context.Background())
	return ing
}

func TestParseLine(t *testing.T) {
	ing := &localIngress{}

	tests := []struct {
		name     string
		input    string
		expected *ingress.Rule
	}{
		{
			name:     "single hostname with endpoint",
			input:    "example.com tunnel-1",
			expected: &ingress.Rule{Hostname: "example.com", Endpoint: "tunnel-1"},
		},
		{
			name:     "wildcard hostname",
			input:    "*.example.com tunnel-1",
			expected: &ingress.Rule{Hostname: "*.example.com", Endpoint: "tunnel-1"},
		},
		{
			name:     "dot-prefix wildcard",
			input:    ".example.com tunnel-1",
			expected: &ingress.Rule{Hostname: ".example.com", Endpoint: "tunnel-1"},
		},
		{
			name:     "comment line",
			input:    "# this is a comment",
			expected: nil,
		},
		{
			name:     "inline comment",
			input:    "example.com tunnel-1 # some comment",
			expected: &ingress.Rule{Hostname: "example.com", Endpoint: "tunnel-1"},
		},
		{
			name:     "tab separated",
			input:    "example.com\ttunnel-1",
			expected: &ingress.Rule{Hostname: "example.com", Endpoint: "tunnel-1"},
		},
		{
			name:     "mixed spaces and tabs",
			input:    "example.com \t tunnel-1",
			expected: &ingress.Rule{Hostname: "example.com", Endpoint: "tunnel-1"},
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
			name:     "hostname only no endpoint",
			input:    "example.com",
			expected: nil,
		},
		{
			name:     "comment only with whitespace",
			input:    "  # comment",
			expected: nil,
		},
		{
			name:     "extra whitespace between fields",
			input:    "example.com    tunnel-1",
			expected: &ingress.Rule{Hostname: "example.com", Endpoint: "tunnel-1"},
		},
		{
			name:     "# only",
			input:    "#",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ing.parseLine(tt.input)
			if tt.expected == nil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil rule")
			}
			if got.Hostname != tt.expected.Hostname {
				t.Errorf("Hostname: expected %q, got %q", tt.expected.Hostname, got.Hostname)
			}
			if got.Endpoint != tt.expected.Endpoint {
				t.Errorf("Endpoint: expected %q, got %q", tt.expected.Endpoint, got.Endpoint)
			}
		})
	}
}

func TestParseRules(t *testing.T) {
	ing := &localIngress{}

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
			input:    "example.com tunnel-1\n",
			expected: 1,
		},
		{
			name:     "multiple lines",
			input:    "example.com tunnel-1\nfoo.com tunnel-2\n",
			expected: 2,
		},
		{
			name:     "with comments and blanks",
			input:    "# comment\nexample.com tunnel-1\n\n# another comment\nfoo.com tunnel-2\n",
			expected: 2,
		},
		{
			name:     "skips invalid lines",
			input:    "invalid\n# comment\nexample.com tunnel-1\n\nonlyhost\n",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r io.Reader
			if tt.input != "" {
				r = strings.NewReader(tt.input)
			}
			got, err := ing.parseRules(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.expected {
				t.Fatalf("expected %d rules, got %d", tt.expected, len(got))
			}
		})
	}
}

func TestParseRulesNilLine(t *testing.T) {
	// parseLine returns nil for a #-only comment, parseRules must not panic (regression test for nil deref bug)
	ing := &localIngress{}
	rules, err := ing.parseRules(strings.NewReader("# comment\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules from comment-only input, got %d", len(rules))
	}
}

func TestGetRuleExactMatch(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil {
		t.Fatal("expected rule for 'example.com'")
	}
	if rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected endpoint 'tunnel-1', got %q", rule.Endpoint)
	}
}

func TestGetRuleNoMatch(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "unknown.com")
	if rule != nil {
		t.Fatal("expected nil rule for 'unknown.com'")
	}
}

func TestGetRuleDotPrefixWildcard(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: ".example.com", Endpoint: "tunnel-1"},
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
			rule := ing.GetRule(context.Background(), tt.host)
			if (rule != nil) != tt.ok {
				t.Errorf("GetRule(%q) ok = %v, want %v", tt.host, rule != nil, tt.ok)
			}
		})
	}
}

func TestGetRuleStarWildcard(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "*.example.com", Endpoint: "tunnel-1"},
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
			rule := ing.GetRule(context.Background(), tt.host)
			if (rule != nil) != tt.ok {
				t.Errorf("GetRule(%q) ok = %v, want %v", tt.host, rule != nil, tt.ok)
			}
		})
	}
}

func TestGetRuleSubdomainWildcard(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: ".example.com", Endpoint: "tunnel-1"},
		{Hostname: ".foo.example.com", Endpoint: "tunnel-2"},
	}))

	// more specific match should win
	rule := ing.GetRule(context.Background(), "foo.example.com")
	if rule == nil {
		t.Fatal("expected rule for 'foo.example.com'")
	}
	if rule.Endpoint != "tunnel-2" {
		t.Fatalf("expected 'tunnel-2' (more specific), got %q", rule.Endpoint)
	}

	// less specific fallback
	rule = ing.GetRule(context.Background(), "bar.example.com")
	if rule == nil {
		t.Fatal("expected rule for 'bar.example.com'")
	}
	if rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %q", rule.Endpoint)
	}
}

func TestGetRuleDeeperSubdomainMatch(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: ".example.com", Endpoint: "tunnel-1"},
		{Hostname: ".b.example.com", Endpoint: "tunnel-2"},
	}))

	rule := ing.GetRule(context.Background(), "a.b.example.com")
	if rule == nil {
		t.Fatal("expected rule for 'a.b.example.com'")
	}
	if rule.Endpoint != "tunnel-2" {
		t.Fatalf("expected 'tunnel-2' (more specific), got %q", rule.Endpoint)
	}

	rule = ing.GetRule(context.Background(), "c.example.com")
	if rule == nil {
		t.Fatal("expected rule for 'c.example.com'")
	}
	if rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %q", rule.Endpoint)
	}
}

func TestGetRulePortStripping(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "example.com:443")
	if rule == nil {
		t.Fatal("expected rule for 'example.com:443'")
	}
	if rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %q", rule.Endpoint)
	}
}

func TestGetRuleEmptyHost(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "")
	if rule != nil {
		t.Fatal("expected nil rule for empty host")
	}
}

func TestGetRuleEmptyMappings(t *testing.T) {
	ing := newTestIngress()

	rule := ing.GetRule(context.Background(), "example.com")
	if rule != nil {
		t.Fatal("expected nil rule with empty rules")
	}
}

func TestGetRuleNilReceiver(t *testing.T) {
	var ing *localIngress
	rule := ing.GetRule(context.Background(), "example.com")
	if rule != nil {
		t.Fatal("expected nil rule from nil receiver")
	}
}

func TestSetRule(t *testing.T) {
	ing := newTestIngress()
	ok := ing.SetRule(context.Background(), &ingress.Rule{
		Hostname: "example.com",
		Endpoint: "tunnel-1",
	})
	if ok {
		t.Fatal("SetRule should return false (not supported by localIngress)")
	}
}

func TestSetRuleNilRule(t *testing.T) {
	ing := newTestIngress()
	ok := ing.SetRule(context.Background(), nil)
	if ok {
		t.Fatal("SetRule with nil rule should return false")
	}
}

func TestReload(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatal("initial rule not found")
	}

	ing.options.rules = []*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-2"},
	}
	_ = ing.reload(context.Background())

	rule = ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-2" {
		t.Fatalf("expected 'tunnel-2' after reload, got %v", rule)
	}
}

func TestReloadRejectsEmptyRule(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "", Endpoint: "tunnel-1"},
		{Hostname: "example.com", Endpoint: ""},
		{Hostname: "valid.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "valid.com")
	if rule == nil {
		t.Fatal("expected rule for 'valid.com'")
	}

	rule = ing.GetRule(context.Background(), "")
	if rule != nil {
		t.Fatal("expected nil for empty-hostname rule")
	}
}

func TestReloadWildcardKeyConversion(t *testing.T) {
	// *.example.com should be stored under .example.com key
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "*.example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "sub.example.com")
	if rule == nil {
		t.Fatal("expected rule for 'sub.example.com' via *-wildcard")
	}
	if rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %q", rule.Endpoint)
	}
}

func TestClose(t *testing.T) {
	ing := NewIngress().(*localIngress)
	err := ing.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// second Close should be safe (cancelFunc is idempotent via context.CancelFunc)
	err = ing.Close()
	if err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestCloseClosesLoaders(t *testing.T) {
	cl := &closeTrackingLoader{}
	ing := newTestIngress(
		FileLoaderOption(cl),
		RedisLoaderOption(cl),
		HTTPLoaderOption(cl),
	)

	_ = ing.Close()

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

type testLoader struct {
	data string
}

func (l *testLoader) Load(_ context.Context) (io.Reader, error) {
	return strings.NewReader(l.data), nil
}

func (l *testLoader) Close() error { return nil }

func TestLoadFileLoader(t *testing.T) {
	ing := newTestIngress(
		FileLoaderOption(&testLoader{data: "example.com tunnel-1\n"}),
	)

	_ = ing.reload(context.Background())

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
	}
}

func TestLoadHTTPLoader(t *testing.T) {
	ing := newTestIngress(
		HTTPLoaderOption(&testLoader{data: "example.com tunnel-1\n"}),
	)

	_ = ing.reload(context.Background())

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
	}
}

func TestLoadRedisLoader(t *testing.T) {
	ing := newTestIngress(
		RedisLoaderOption(&testLoader{data: "example.com tunnel-1\n"}),
	)

	_ = ing.reload(context.Background())

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
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
	ing := newTestIngress(
		FileLoaderOption(&testLister{lines: []string{"example.com tunnel-1", "foo.com tunnel-2"}}),
	)

	_ = ing.reload(context.Background())

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
	}

	rule = ing.GetRule(context.Background(), "foo.com")
	if rule == nil || rule.Endpoint != "tunnel-2" {
		t.Fatalf("expected 'tunnel-2', got %v", rule)
	}
}

func TestLoadRedisLoaderAsLister(t *testing.T) {
	ing := newTestIngress(
		RedisLoaderOption(&testLister{lines: []string{"example.com tunnel-1"}}),
	)

	_ = ing.reload(context.Background())

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
	}
}

func TestLoaderPrecedence(t *testing.T) {
	// loader rules should override option rules with the same hostname
	ing := newTestIngress(
		RulesOption([]*ingress.Rule{
			{Hostname: "example.com", Endpoint: "tunnel-static"},
		}),
		FileLoaderOption(&testLoader{data: "example.com tunnel-loader\n"}),
	)

	_ = ing.reload(context.Background())

	rule := ing.GetRule(context.Background(), "example.com")
	if rule == nil || rule.Endpoint != "tunnel-loader" {
		t.Fatalf("expected 'tunnel-loader' (loader overrides static), got %v", rule)
	}
}

func TestReloadPeriodOption(t *testing.T) {
	period := 5 * time.Minute
	ing := newTestIngress(ReloadPeriodOption(period))
	if ing.options.period != period {
		t.Fatalf("expected period %v, got %v", period, ing.options.period)
	}
}

func TestLoggerOption(t *testing.T) {
	ing := NewIngress().(*localIngress)
	if ing.logger == nil {
		t.Fatal("expected non-nil default logger")
	}
}

func TestPeriodReloadNegativePeriod(t *testing.T) {
	ing := NewIngress(
		ReloadPeriodOption(-1*time.Second),
		LoggerOption(xlogger.Nop()),
	).(*localIngress)

	err := ing.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestGetRuleContextCancellation(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rule := ing.GetRule(ctx, "example.com")
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
	}
}

func TestGetRuleWithOptions(t *testing.T) {
	ing := newTestIngress(RulesOption([]*ingress.Rule{
		{Hostname: "example.com", Endpoint: "tunnel-1"},
	}))

	rule := ing.GetRule(context.Background(), "example.com", ingress.WithService("my-svc"))
	if rule == nil || rule.Endpoint != "tunnel-1" {
		t.Fatalf("expected 'tunnel-1', got %v", rule)
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
