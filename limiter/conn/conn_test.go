package conn

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	limiter "github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
	"github.com/yl2chen/cidranger"
)

type fakeLoader struct {
	data    string
	listErr error
	loadErr error
	closed  bool
}

func (l *fakeLoader) List(ctx context.Context) ([]string, error) {
	if l.listErr != nil {
		return nil, l.listErr
	}
	if l.data == "" {
		return nil, nil
	}
	return strings.Split(l.data, "\n"), nil
}

func (l *fakeLoader) Load(ctx context.Context) (io.Reader, error) {
	if l.loadErr != nil {
		return nil, l.loadErr
	}
	return strings.NewReader(l.data), nil
}

func (l *fakeLoader) Close() error {
	l.closed = true
	return nil
}

func nopLogger() logger.Logger {
	return xlogger.Nop()
}

func TestParseLine(t *testing.T) {
	cl := &connLimiter{}

	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1 100", "192.168.1.1 100"},
		{"  192.168.1.1 100  ", "192.168.1.1 100"},
		{"192.168.1.1 100 # comment", "192.168.1.1 100"},
		{"# only comment", ""},
		{"   # indented comment", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := cl.parseLine(tt.input)
		if got != tt.expected {
			t.Errorf("parseLine(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseLimit(t *testing.T) {
	cl := &connLimiter{}

	tests := []struct {
		input string
		key   string
		limit int
	}{
		{"192.168.1.1 100", "192.168.1.1", 100},
		{"192.168.1.1\t100", "192.168.1.1", 100},
		{"192.168.1.1     100", "192.168.1.1", 100},
		{"$ 50", "$", 50},
		{"$$ 20", "$$", 20},
		{"10.0.0.0/8 500", "10.0.0.0/8", 500},
		{"key only", "key", 0},
		{"key invalid", "key", 0},
		{"", "", 0},
	}
	for _, tt := range tests {
		key, limit := cl.parseLimit(tt.input)
		if key != tt.key || limit != tt.limit {
			t.Errorf("parseLimit(%q) = (%q, %d), want (%q, %d)", tt.input, key, limit, tt.key, tt.limit)
		}
	}
}

func TestParsePatterns(t *testing.T) {
	cl := &connLimiter{}

	patterns, err := cl.parsePatterns(strings.NewReader("192.168.1.1 10\n10.0.0.1 20\n# comment\n\n  172.16.0.1 30  \n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 3 {
		t.Fatalf("expected 3 patterns, got %d: %v", len(patterns), patterns)
	}
}

func TestParsePatterns_NilReader(t *testing.T) {
	cl := &connLimiter{}
	patterns, err := cl.parsePatterns(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 0 {
		t.Fatal("expected no patterns from nil reader")
	}
}

func TestLoad_NoLoaders(t *testing.T) {
	cl := &connLimiter{options: options{}, logger: nopLogger()}
	patterns, err := cl.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 0 {
		t.Fatalf("expected 0 patterns, got %d", len(patterns))
	}
}

func TestLoad_FileLister(t *testing.T) {
	fl := &fakeLoader{data: "10.0.0.1 10\n# ignored\n10.0.0.2 20"}
	cl := &connLimiter{
		options: options{fileLoader: fl},
		logger:  nopLogger(),
	}
	patterns, err := cl.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d: %v", len(patterns), patterns)
	}
}

func TestLoad_RedisLoader(t *testing.T) {
	rl := &fakeLoader{data: "10.0.0.1 5"}
	cl := &connLimiter{
		options: options{redisLoader: rl},
		logger:  nopLogger(),
	}
	patterns, err := cl.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// redis list items are NOT parseLine-filtered (raw).
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}
}

func TestLoad_HTTPLoader(t *testing.T) {
	hl := &fakeLoader{data: "10.0.0.1 5\n10.0.0.2 3"}
	cl := &connLimiter{
		options: options{httpLoader: hl},
		logger:  nopLogger(),
	}
	patterns, err := cl.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}
}

func TestLoad_FileListerError(t *testing.T) {
	fl := &fakeLoader{data: "", listErr: io.ErrUnexpectedEOF}
	cl := &connLimiter{
		options: options{fileLoader: fl},
		logger:  nopLogger(),
	}
	patterns, err := cl.load(context.Background())
	if err != nil {
		t.Fatal("load should not return error on loader failure")
	}
	if len(patterns) != 0 {
		t.Fatalf("expected 0 patterns, got %d", len(patterns))
	}
}

func TestReload_StaticLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl := &connLimiter{
		options: options{
			limits: []string{"192.168.1.1 3", "10.0.0.0/8 10", "$ 100"},
		},
		ipLimits:   make(map[string]ConnLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		limits:     make(map[string]limiter.Limiter),
		logger:     nopLogger(),
		cancelFunc: cancel,
	}

	if err := cl.reload(ctx); err != nil {
		t.Fatal(err)
	}

	// Global limit applies to any key.
	lim := cl.Limiter("any-key")
	if lim == nil {
		t.Fatal("global limiter should exist")
	}
	if lim.Limit() != 100 {
		t.Fatalf("expected global limit 100, got %d", lim.Limit())
	}
}

// newTestConnLimiter creates a connLimiter with sync reload, no goroutine.
func newTestConnLimiter(limits ...string) *connLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	cl := &connLimiter{
		options:    options{limits: limits},
		ipLimits:   make(map[string]ConnLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		limits:     make(map[string]limiter.Limiter),
		logger:     nopLogger(),
		cancelFunc: cancel,
	}
	_ = cl.reload(ctx)
	return cl
}

func TestReload_ClearsCache(t *testing.T) {
	cl := newTestConnLimiter("192.168.1.1 5")
	defer cl.Close()

	lim := cl.Limiter("192.168.1.1")
	if lim == nil || lim.Limit() != 5 {
		t.Fatal("limiter should exist with limit 5")
	}

	// Reload clears cache and re-parses static limits.
	if err := cl.reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	lim2 := cl.Limiter("192.168.1.1")
	if lim2 == nil {
		t.Fatal("limiter should still exist after reload")
	}
	if lim2.Limit() != 5 {
		t.Fatalf("expected limit 5 after reload, got %d", lim2.Limit())
	}
}

func TestLimiter_NilCacheDoesNotStick(t *testing.T) {
	cl := newTestConnLimiter()
	defer cl.Close()

	// Lookup for a key with no matching limit should NOT cache nil.
	lim := cl.Limiter("10.0.0.1")
	if lim != nil {
		t.Fatal("should be no limiter for 10.0.0.1")
	}

	// Manually add a limit via reload.
	cl.options.limits = []string{"10.0.0.1 3"}
	if err := cl.reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Should now find the limit because nil was not cached.
	lim = cl.Limiter("10.0.0.1")
	if lim == nil {
		t.Fatal("limiter should exist after reload when nil was not cached")
	}
	if lim.Limit() != 3 {
		t.Fatalf("expected limit 3, got %d", lim.Limit())
	}
}

func TestLimiter_IPLimitKey(t *testing.T) {
	cl := newTestConnLimiter("$$ 5")
	defer cl.Close()

	lim := cl.Limiter("10.0.0.1")
	if lim == nil {
		t.Fatal("IP-level limiter should exist")
	}
	if lim.Limit() != 5 {
		t.Fatalf("expected limit 5, got %d", lim.Limit())
	}
}

func TestLimiter_CIDRMatch(t *testing.T) {
	cl := newTestConnLimiter("10.0.0.0/8 7")
	defer cl.Close()

	lim := cl.Limiter("10.1.2.3")
	if lim == nil {
		t.Fatal("CIDR-based limiter should exist for 10.1.2.3")
	}
	if lim.Limit() != 7 {
		t.Fatalf("expected limit 7, got %d", lim.Limit())
	}
}

func TestLimiter_CIDRNoMatch(t *testing.T) {
	cl := newTestConnLimiter("10.0.0.0/8 7")
	defer cl.Close()

	lim := cl.Limiter("192.168.1.1")
	if lim != nil {
		t.Fatal("CIDR-based limiter should not match 192.168.1.1")
	}
}

func TestLimiter_SpecificIPTakesPrecedence(t *testing.T) {
	cl := newTestConnLimiter("10.0.0.0/8 5", "10.1.2.3 2")
	defer cl.Close()

	lim := cl.Limiter("10.1.2.3")
	if lim == nil {
		t.Fatal("specific IP limiter should exist")
	}
	if lim.Limit() != 2 {
		t.Fatalf("expected specific IP limit 2, got %d", lim.Limit())
	}
}

func TestLimiter_GlobalAndIP(t *testing.T) {
	cl := newTestConnLimiter("$$ 5", "$ 10")
	defer cl.Close()

	lim := cl.Limiter("10.0.0.1")
	if lim == nil {
		t.Fatal("should have IP+global limiter")
	}
	if lim.Limit() != 5 {
		t.Fatalf("expected limit 5 (min of 5,10), got %d", lim.Limit())
	}
}

func TestLimiter_NonIPKeyHasGlobalOnly(t *testing.T) {
	cl := newTestConnLimiter("$$ 5", "$ 10")
	defer cl.Close()

	lim := cl.Limiter("not-an-ip")
	if lim == nil {
		t.Fatal("should have limiters")
	}
	// IPLimitKey ($$=5) acts as fallback for any key when no specific IP match.
	// Global ($=10) also applies. Group picks the minimum: 5.
	if lim.Limit() != 5 {
		t.Fatalf("expected limit 5 (min of IP fallback 5 and global 10), got %d", lim.Limit())
	}
}

func TestClose(t *testing.T) {
	fl := &fakeLoader{}
	rl := &fakeLoader{}
	hl := &fakeLoader{}

	cl := NewConnLimiter(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
	).(*connLimiter)

	cl.Close()

	if !fl.closed {
		t.Error("fileLoader was not closed")
	}
	if !rl.closed {
		t.Error("redisLoader was not closed")
	}
	if !hl.closed {
		t.Error("httpLoader was not closed")
	}
}

func TestClose_Idempotent(t *testing.T) {
	fl := &fakeLoader{}
	cl := NewConnLimiter(FileLoaderOption(fl)).(*connLimiter)
	cl.Close()
	cl.Close()
}

func TestLimiter_CachedResult(t *testing.T) {
	cl := newTestConnLimiter("192.168.1.1 5")
	defer cl.Close()

	lim1 := cl.Limiter("192.168.1.1")
	if lim1 == nil {
		t.Fatal("first lookup should return a limiter")
	}

	lim2 := cl.Limiter("192.168.1.1")
	if lim2 != lim1 {
		t.Fatal("second lookup should return cached limiter")
	}
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	cl := newTestConnLimiter("192.168.1.1 1000")
	defer cl.Close()

	var wg sync.WaitGroup
	n := 50
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cl.Limiter("192.168.1.1")
		}()
	}
	wg.Wait()
}

func TestConnLimiter_Interface(t *testing.T) {
	var cl limiter.ConnLimiter = NewConnLimiter()
	if cl == nil {
		t.Fatal("ConnLimiter should not be nil")
	}
}

func TestPeriodReload_ZeroPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl := &connLimiter{
		options: options{period: 0},
		logger:  nopLogger(),
	}

	err := cl.periodReload(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPeriodReload_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := &connLimiter{
		options: options{period: 10 * time.Second},
		logger:  nopLogger(),
	}
	cancel()
	err := cl.periodReload(ctx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
