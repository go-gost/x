package rate

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	limiter "github.com/go-gost/core/limiter/rate"
	xlogger "github.com/go-gost/x/logger"
	"github.com/yl2chen/cidranger"
)

// newTestRateLimiter creates a rateLimiter with synchronous reload, no goroutine.
func newTestRateLimiter(limits ...string) *rateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &rateLimiter{
		options:    options{limits: limits},
		ipLimits:   make(map[string]RateLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		limits:     make(map[string]limiter.Limiter),
		logger:     xlogger.Nop(),
		cancelFunc: cancel,
	}
	_ = rl.reload(ctx)
	return rl
}

// newTestRateLimiterWithLoaders creates a rateLimiter with loaders and sync reload.
func newTestRateLimiterWithLoaders(opts ...Option) *rateLimiter {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rl := &rateLimiter{
		options:    o,
		ipLimits:   make(map[string]RateLimitGenerator),
		cidrLimits: cidranger.NewPCTrieRanger(),
		limits:     make(map[string]limiter.Limiter),
		logger:     o.logger,
		cancelFunc: cancel,
	}
	if rl.logger == nil {
		rl.logger = xlogger.Nop()
	}
	_ = rl.reload(ctx)
	return rl
}

// --- rlimiter tests ---

func TestNewLimiter(t *testing.T) {
	l := NewLimiter(10, 5)
	if l == nil {
		t.Fatal("NewLimiter returned nil")
	}
	if l.Limit() != 10 {
		t.Errorf("Limit() = %v, want 10", l.Limit())
	}
	if !l.Allow(1) {
		t.Error("Allow(1) should be true for new limiter")
	}
}

func TestNewLimiter_ZeroRate(t *testing.T) {
	l := NewLimiter(0, 0)
	if l.Limit() != 0 {
		t.Errorf("Limit() = %v, want 0", l.Limit())
	}
	if l.Allow(1) {
		t.Error("Allow(1) should be false with rate 0, burst 0")
	}
}

func TestNewLimiter_AllowMany(t *testing.T) {
	l := NewLimiter(100, 10)
	if !l.Allow(5) {
		t.Error("Allow(5) should be true within burst")
	}
	if l.Allow(100) {
		t.Error("Allow(100) should be false when exceeding burst")
	}
}

// --- limiterGroup tests ---

func TestNewLimiterGroup_Empty(t *testing.T) {
	g := newLimiterGroup()
	if g.Limit() != 0 {
		t.Errorf("Limit() = %v, want 0", g.Limit())
	}
	if !g.Allow(1) {
		t.Error("Allow(1) should be true for empty group")
	}
}

func TestNewLimiterGroup_Single(t *testing.T) {
	l := NewLimiter(100, 10)
	g := newLimiterGroup(l)
	if g.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100", g.Limit())
	}
	if !g.Allow(1) {
		t.Error("Allow(1) should be true")
	}
}

func TestNewLimiterGroup_AllAllow(t *testing.T) {
	l1 := NewLimiter(100, 10)
	l2 := NewLimiter(200, 10)
	g := newLimiterGroup(l1, l2)
	if g.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100 (most restrictive)", g.Limit())
	}
	if !g.Allow(1) {
		t.Error("Allow(1) should be true when all allow")
	}
}

func TestNewLimiterGroup_FirstDenies_NoTokenWaste(t *testing.T) {
	l1 := NewLimiter(0, 0) // always denies
	l2 := newCountingLimiter(100, 100)
	g := newLimiterGroup(l1, l2)

	if g.Allow(1) {
		t.Error("Allow(1) should be false when first limiter denies")
	}
	if l2.allowCalls > 0 {
		t.Errorf("later limiter Allow called %d times, want 0 (tokens wasted on denial)", l2.allowCalls)
	}
}

func TestNewLimiterGroup_SecondDenies_EarlyReturn(t *testing.T) {
	l1 := NewLimiter(100, 100) // allows
	l2 := NewLimiter(0, 0)     // always denies
	g := newLimiterGroup(l1, l2)

	if g.Allow(1) {
		t.Error("Allow(1) should be false when second limiter denies")
	}
}

func TestNewLimiterGroup_SortedByLimit(t *testing.T) {
	l1 := NewLimiter(200, 10)
	l2 := NewLimiter(50, 10)
	l3 := NewLimiter(100, 10)
	g := newLimiterGroup(l1, l2, l3)

	if g.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50 (most restrictive)", g.Limit())
	}
}

type countingLimiter struct {
	limiter.Limiter
	allowCalls int
}

func newCountingLimiter(r float64, b int) *countingLimiter {
	return &countingLimiter{Limiter: NewLimiter(r, b)}
}

func (l *countingLimiter) Allow(n int) bool {
	l.allowCalls++
	return l.Limiter.Allow(n)
}

// --- Generator tests ---

func TestNewRateLimitGenerator_Positive(t *testing.T) {
	g := NewRateLimitGenerator(10)
	l := g.Limiter()
	if l == nil {
		t.Fatal("Limiter() should not be nil for positive rate")
	}
	if l.Limit() != 10 {
		t.Errorf("Limit() = %v, want 10", l.Limit())
	}
	l2 := g.Limiter()
	if l == l2 {
		t.Error("each Limiter() call should create a new limiter")
	}
}

func TestNewRateLimitGenerator_Zero(t *testing.T) {
	g := NewRateLimitGenerator(0)
	if l := g.Limiter(); l != nil {
		t.Error("Limiter() should be nil for zero rate")
	}
}

func TestNewRateLimitGenerator_Negative(t *testing.T) {
	g := NewRateLimitGenerator(-5)
	if l := g.Limiter(); l != nil {
		t.Error("Limiter() should be nil for negative rate")
	}
}

func TestNewRateLimitSingleGenerator_Positive(t *testing.T) {
	g := NewRateLimitSingleGenerator(10)
	l := g.Limiter()
	if l == nil {
		t.Fatal("Limiter() should not be nil for positive rate")
	}
	if l.Limit() != 10 {
		t.Errorf("Limit() = %v, want 10", l.Limit())
	}
	l2 := g.Limiter()
	if l != l2 {
		t.Error("should return the same limiter each call")
	}
}

func TestNewRateLimitSingleGenerator_Zero(t *testing.T) {
	g := NewRateLimitSingleGenerator(0)
	if l := g.Limiter(); l != nil {
		t.Error("Limiter() should be nil for zero rate")
	}
}

// --- rateLimiter tests using sync reload helper ---

func TestRateLimiter_Defaults(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Close()

	if l := rl.Limiter("192.168.1.1"); l != nil {
		t.Error("should return nil when no limits configured")
	}
}

func TestRateLimiter_WithLimits(t *testing.T) {
	rl := newTestRateLimiter("$ 100")
	defer rl.Close()

	l := rl.Limiter("any-key")
	if l == nil {
		t.Fatal("should have a global limiter")
	}
	if l.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100", l.Limit())
	}
}

func TestRateLimiter_IPExactMatch(t *testing.T) {
	rl := newTestRateLimiter("192.168.1.1 50", "$ 100")
	defer rl.Close()

	l := rl.Limiter("192.168.1.1")
	if l == nil {
		t.Fatal("should have a limiter for exact IP")
	}
	if l.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50", l.Limit())
	}

	l2 := rl.Limiter("10.0.0.1")
	if l2 == nil {
		t.Fatal("should have global limiter")
	}
	if l2.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100", l2.Limit())
	}
}

func TestRateLimiter_CIDRMatch(t *testing.T) {
	rl := newTestRateLimiter("192.168.0.0/16 30", "$ 100")
	defer rl.Close()

	l := rl.Limiter("192.168.1.50")
	if l == nil {
		t.Fatal("should have a CIDR limiter")
	}
	if l.Limit() != 30 {
		t.Errorf("Limit() = %v, want 30", l.Limit())
	}
}

func TestRateLimiter_IPExactOverridesCIDR(t *testing.T) {
	rl := newTestRateLimiter("192.168.0.0/16 30", "192.168.1.1 50", "$ 100")
	defer rl.Close()

	l := rl.Limiter("192.168.1.1")
	if l == nil {
		t.Fatal("should have a limiter for exact IP")
	}
	if l.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50 (exact IP should override CIDR)", l.Limit())
	}
}

func TestRateLimiter_IPLimitKeyFallback(t *testing.T) {
	rl := newTestRateLimiter("$$ 25", "$ 100")
	defer rl.Close()

	l := rl.Limiter("10.0.0.1")
	if l == nil {
		t.Fatal("should have a limiter (IPLimitKey fallback)")
	}
	if l.Limit() != 25 {
		t.Errorf("Limit() = %v, want 25", l.Limit())
	}
}

func TestRateLimiter_IPLimitKeyFallback_CIDRHigherPriority(t *testing.T) {
	rl := newTestRateLimiter("192.168.0.0/16 30", "$$ 25", "$ 100")
	defer rl.Close()

	l := rl.Limiter("192.168.1.50")
	if l == nil {
		t.Fatal("should have a CIDR limiter")
	}
	if l.Limit() != 30 {
		t.Errorf("Limit() = %v, want 30 (CIDR should override IPLimitKey)", l.Limit())
	}

	l2 := rl.Limiter("10.0.0.1")
	if l2 == nil {
		t.Fatal("should have IPLimitKey fallback")
	}
	if l2.Limit() != 25 {
		t.Errorf("Limit() = %v, want 25", l2.Limit())
	}
}

func TestRateLimiter_GlobalLimitOnly(t *testing.T) {
	rl := newTestRateLimiter("$ 50")
	defer rl.Close()

	l := rl.Limiter("192.168.1.1")
	if l == nil {
		t.Fatal("should have global limiter for IP")
	}
	if l.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50", l.Limit())
	}

	l2 := rl.Limiter("some-service")
	if l2 == nil {
		t.Fatal("should have global limiter for non-IP key")
	}
}

func TestRateLimiter_NonIPKey(t *testing.T) {
	rl := newTestRateLimiter("$ 100")
	defer rl.Close()

	l := rl.Limiter("my-service")
	if l == nil {
		t.Fatal("should have global limiter")
	}
	if l.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100", l.Limit())
	}
}

func TestRateLimiter_LimiterCache(t *testing.T) {
	rl := newTestRateLimiter("$ 100")
	defer rl.Close()

	l1 := rl.Limiter("test-key")
	l2 := rl.Limiter("test-key")
	if l1 != l2 {
		t.Error("Limiter() should return cached limiter for same key")
	}
}

func TestRateLimiter_ZeroLimit(t *testing.T) {
	rl := newTestRateLimiter("192.168.1.1 0", "$ 100")
	defer rl.Close()

	// Zero limit is skipped in reload, falls through to global
	l := rl.Limiter("192.168.1.1")
	if l == nil {
		t.Fatal("should fall through to global limit")
	}
	if l.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100 (global fallback for zero limit)", l.Limit())
	}
}

// --- parseLimit tests ---

func TestRateLimiter_ParseLimit_Normal(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("192.168.1.1 100")
	if key != "192.168.1.1" {
		t.Errorf("key = %q, want %q", key, "192.168.1.1")
	}
	if limit != 100 {
		t.Errorf("limit = %v, want 100", limit)
	}
}

func TestRateLimiter_ParseLimit_WithTabs(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("192.168.1.1\t50")
	if key != "192.168.1.1" {
		t.Errorf("key = %q, want %q", key, "192.168.1.1")
	}
	if limit != 50 {
		t.Errorf("limit = %v, want 50", limit)
	}
}

func TestRateLimiter_ParseLimit_ExtraWhitespace(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("  192.168.1.1   100  ")
	if key != "192.168.1.1" {
		t.Errorf("key = %q, want %q", key, "192.168.1.1")
	}
	if limit != 100 {
		t.Errorf("limit = %v, want 100", limit)
	}
}

func TestRateLimiter_ParseLimit_SingleField(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("192.168.1.1")
	if key != "" || limit != 0 {
		t.Errorf("single field should return empty: key=%q limit=%v", key, limit)
	}
}

func TestRateLimiter_ParseLimit_Empty(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("")
	if key != "" || limit != 0 {
		t.Errorf("empty string should return zero values: key=%q limit=%v", key, limit)
	}
}

func TestRateLimiter_ParseLimit_InvalidFloat(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("key abc")
	if key != "key" || limit != 0 {
		t.Errorf("invalid float should return limit=0: key=%q limit=%v", key, limit)
	}
}

func TestRateLimiter_ParseLimit_GlobalKey(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("$ 200")
	if key != "$" {
		t.Errorf("key = %q, want %q", key, "$")
	}
	if limit != 200 {
		t.Errorf("limit = %v, want 200", limit)
	}
}

func TestRateLimiter_ParseLimit_IPLimitKey(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("$$ 75")
	if key != "$$" {
		t.Errorf("key = %q, want %q", key, "$$")
	}
	if limit != 75 {
		t.Errorf("limit = %v, want 75", limit)
	}
}

func TestRateLimiter_ParseLimit_CIDR(t *testing.T) {
	rl := &rateLimiter{}
	key, limit := rl.parseLimit("10.0.0.0/8 60")
	if key != "10.0.0.0/8" {
		t.Errorf("key = %q, want %q", key, "10.0.0.0/8")
	}
	if limit != 60 {
		t.Errorf("limit = %v, want 60", limit)
	}
}

// --- parseLine tests ---

func TestRateLimiter_ParseLine_Comment(t *testing.T) {
	rl := &rateLimiter{}
	if s := rl.parseLine("192.168.1.1 100 # my comment"); s != "192.168.1.1 100" {
		t.Errorf("parseLine = %q, want %q", s, "192.168.1.1 100")
	}
}

func TestRateLimiter_ParseLine_OnlyComment(t *testing.T) {
	rl := &rateLimiter{}
	if s := rl.parseLine("# just a comment"); s != "" {
		t.Errorf("parseLine = %q, want empty", s)
	}
}

func TestRateLimiter_ParseLine_Whitespace(t *testing.T) {
	rl := &rateLimiter{}
	if s := rl.parseLine("  192.168.1.1 100  "); s != "192.168.1.1 100" {
		t.Errorf("parseLine = %q, want %q", s, "192.168.1.1 100")
	}
}

// --- parsePatterns tests ---

func TestRateLimiter_ParsePatterns(t *testing.T) {
	rl := &rateLimiter{}
	r := strings.NewReader("192.168.1.1 100\n10.0.0.0/8 50\n# comment\n$ 200\n")
	patterns, err := rl.parsePatterns(r)
	if err != nil {
		t.Fatalf("parsePatterns err: %v", err)
	}
	if len(patterns) != 3 {
		t.Fatalf("got %d patterns, want 3: %v", len(patterns), patterns)
	}
	if patterns[0] != "192.168.1.1 100" {
		t.Errorf("patterns[0] = %q", patterns[0])
	}
	if patterns[1] != "10.0.0.0/8 50" {
		t.Errorf("patterns[1] = %q", patterns[1])
	}
	if patterns[2] != "$ 200" {
		t.Errorf("patterns[2] = %q", patterns[2])
	}
}

func TestRateLimiter_ParsePatterns_NilReader(t *testing.T) {
	rl := &rateLimiter{}
	patterns, err := rl.parsePatterns(nil)
	if err != nil {
		t.Fatalf("parsePatterns err: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("got %d patterns, want 0", len(patterns))
	}
}

// --- reload tests ---

func TestRateLimiter_Reload_ClearsCache(t *testing.T) {
	rl := newTestRateLimiter("$ 100")
	defer rl.Close()

	l1 := rl.Limiter("test-key")

	_ = rl.reload(context.Background())

	l2 := rl.Limiter("test-key")
	if l1 == l2 {
		t.Error("cache should be cleared after reload, but got same limiter")
	}
	if l2.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100 after reload", l2.Limit())
	}
}

func TestRateLimiter_Reload_UpdatesLimits(t *testing.T) {
	rl := newTestRateLimiter("$ 50")
	defer rl.Close()

	l := rl.Limiter("any")
	if l.Limit() != 50 {
		t.Fatalf("initial limit = %v, want 50", l.Limit())
	}

	rl.options.limits = []string{"$ 200"}
	_ = rl.reload(context.Background())

	l = rl.Limiter("any")
	if l.Limit() != 200 {
		t.Errorf("Limit() = %v, want 200 after reload", l.Limit())
	}
}

// --- load tests with fake loaders ---

type fakeLoader struct {
	data   []string
	closed bool
	mu     sync.Mutex
}

func (f *fakeLoader) Load(ctx context.Context) (io.Reader, error) {
	if f.data == nil {
		return nil, nil
	}
	return bytes.NewReader([]byte(strings.Join(f.data, "\n"))), nil
}

func (f *fakeLoader) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

type fakeLister struct {
	fakeLoader
}

func (f *fakeLister) List(ctx context.Context) ([]string, error) {
	return f.data, nil
}

func TestRateLimiter_Load_FileLoader(t *testing.T) {
	fl := &fakeLoader{data: []string{"$ 30"}}
	rl := newTestRateLimiterWithLoaders(FileLoaderOption(fl))
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 30 {
		t.Fatalf("Limit() = %v, want 30", l.Limit())
	}
}

func TestRateLimiter_Load_FileLister(t *testing.T) {
	fl := &fakeLister{fakeLoader{data: []string{"$ 30"}}}
	rl := newTestRateLimiterWithLoaders(FileLoaderOption(fl))
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 30 {
		t.Fatalf("Limit() = %v, want 30", l.Limit())
	}
}

func TestRateLimiter_Load_RedisLoader(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(RedisLoaderOption(&fakeLoader{data: []string{"$ 40"}}))
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 40 {
		t.Fatalf("Limit() = %v, want 40", l.Limit())
	}
}

func TestRateLimiter_Load_RedisLister(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(RedisLoaderOption(&fakeLister{fakeLoader{data: []string{"$ 45"}}}))
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 45 {
		t.Fatalf("Limit() = %v, want 45", l.Limit())
	}
}

func TestRateLimiter_Load_HTTPLoader(t *testing.T) {
	hl := &fakeLoader{data: []string{"$ 35"}}
	rl := newTestRateLimiterWithLoaders(HTTPLoaderOption(hl))
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 35 {
		t.Fatalf("Limit() = %v, want 35", l.Limit())
	}
}

func TestRateLimiter_Load_MergesLoaders(t *testing.T) {
	// File loader: global $=50; HTTP loader: exact IP 192.168.1.1=20; static: CIDR =15.
	// All limits are composed with the global limit via limiterGroup, so the
	// effective limit shown by Limit() is the most restrictive (lowest value).
	fl := &fakeLoader{data: []string{"$ 50"}}
	hl := &fakeLoader{data: []string{"192.168.1.1 20"}}
	rl := newTestRateLimiterWithLoaders(
		FileLoaderOption(fl),
		HTTPLoaderOption(hl),
		LimitsOption("10.0.0.0/8 15"),
	)
	defer rl.Close()

	// Non-IP key: only global
	if l := rl.Limiter("key"); l == nil || l.Limit() != 50 {
		t.Errorf("Global limit = %v, want 50", l.Limit())
	}
	// Exact IP (20) + global (50) → min = 20
	if l := rl.Limiter("192.168.1.1"); l == nil || l.Limit() != 20 {
		t.Errorf("Exact IP limit = %v, want 20", l.Limit())
	}
	// CIDR (15) + global (50) → min = 15
	if l := rl.Limiter("10.0.0.50"); l == nil || l.Limit() != 15 {
		t.Errorf("CIDR limit = %v, want 15", l.Limit())
	}
}

func TestRateLimiter_Load_NilLoaders(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(
		FileLoaderOption(nil),
		RedisLoaderOption(nil),
		HTTPLoaderOption(nil),
		LimitsOption("$ 50"),
	)
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50", l.Limit())
	}
}

// --- Close tests ---

func TestRateLimiter_Close_ClosesAllLoaders(t *testing.T) {
	fl := &fakeLoader{data: []string{"$ 30"}}
	rl := &fakeLoader{data: []string{"$ 30"}}
	hl := &fakeLoader{data: []string{"$ 30"}}

	lim := NewRateLimiter(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
	)
	lim.(*rateLimiter).Close()

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

func TestRateLimiter_Close_NilLoaders(t *testing.T) {
	rl := newTestRateLimiter()
	err := rl.Close()
	if err != nil {
		t.Errorf("Close() err = %v, want nil", err)
	}
}

func TestRateLimiter_Close_Idempotent(t *testing.T) {
	rl := newTestRateLimiter()
	rl.Close()
	// Second close should not panic
	rl.Close()
}

// --- ReloadPeriodOption tests ---

func TestReloadPeriodOption_Zero(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(ReloadPeriodOption(0))
	defer rl.Close()
	// periodReload runs once then returns; no goroutine leak
}

func TestReloadPeriodOption_Short(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(ReloadPeriodOption(500 * time.Millisecond))
	defer rl.Close()
	// Should be clamped to 1 second minimum internally
}

// --- LoggerOption tests ---

func TestLoggerOption(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(LoggerOption(nil))
	defer rl.Close()
	// Logger set to Nop in constructor when nil; no limits means nil limiter
	l := rl.Limiter("key")
	if l != nil {
		t.Error("should return nil with no limits configured")
	}
}

// --- Comment and whitespace handling in load ---

func TestRateLimiter_Load_CommentsAndWhitespace(t *testing.T) {
	fl := &fakeLoader{data: []string{
		"# header comment",
		"  192.168.1.1   100  ",
		"10.0.0.0/8\t50",
		"# another comment",
		"",
	}}
	rl := newTestRateLimiterWithLoaders(FileLoaderOption(fl))
	defer rl.Close()

	l := rl.Limiter("192.168.1.1")
	if l == nil || l.Limit() != 100 {
		t.Errorf("Limit() = %v, want 100", l.Limit())
	}

	l2 := rl.Limiter("10.0.0.50")
	if l2 == nil || l2.Limit() != 50 {
		t.Errorf("CIDR Limit() = %v, want 50", l2.Limit())
	}
}

// --- IPLimitKey generates per-IP limiters ---

func TestRateLimiter_IPLimitKey_GeneratesPerIPLimiters(t *testing.T) {
	rl := newTestRateLimiter("$$ 25", "$ 100")
	defer rl.Close()

	l1 := rl.Limiter("10.0.0.1")
	l2 := rl.Limiter("10.0.0.2")
	if l1 == nil || l2 == nil {
		t.Fatal("should have per-IP limiters")
	}
	if l1 == l2 {
		t.Error("different IPs should get different limiters from IPLimitKey")
	}
	if l1.Limit() != 25 || l2.Limit() != 25 {
		t.Errorf("per-IP limits should be 25, got %v and %v", l1.Limit(), l2.Limit())
	}
}

// --- Error loader ---

type errorLoader struct{}

func (e *errorLoader) Load(ctx context.Context) (io.Reader, error) {
	return nil, io.ErrUnexpectedEOF
}
func (e *errorLoader) Close() error { return nil }

func TestRateLimiter_Load_ErrorLoader(t *testing.T) {
	rl := newTestRateLimiterWithLoaders(
		FileLoaderOption(&errorLoader{}),
		LimitsOption("$ 50"),
	)
	defer rl.Close()

	l := rl.Limiter("key")
	if l == nil || l.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50 (fallback to static)", l.Limit())
	}
}

// --- Loader data overrides static for same key ---

func TestRateLimiter_StaticVsLoadedPriority(t *testing.T) {
	fl := &fakeLoader{data: []string{"$ 200"}}
	rl := newTestRateLimiterWithLoaders(
		FileLoaderOption(fl),
		LimitsOption("$ 50"),
	)
	defer rl.Close()

	// In reload: lines = append(l.options.limits, v...); static first, loaded second.
	// For map assignment, later value wins. So loader overrides static for same key.
	l := rl.Limiter("key")
	if l == nil || l.Limit() != 200 {
		t.Errorf("Limit() = %v, want 200 (loader overrides static for same key)", l.Limit())
	}
}

// --- CIDR exact IP precedence over CIDR range ---

func TestRateLimiter_ExactIPPrecedesCIDRInReload(t *testing.T) {
	rl := newTestRateLimiter("192.168.0.0/16 30", "192.168.1.1 50")
	defer rl.Close()

	// The exact IP entry comes after the CIDR entry in the lines list,
	// so it overwrites the CIDR-based entry in the map.
	l := rl.Limiter("192.168.1.1")
	if l == nil || l.Limit() != 50 {
		t.Errorf("Limit() = %v, want 50 (exact IP should override CIDR)", l.Limit())
	}

	// Other IPs in the CIDR range still get the CIDR limit.
	l2 := rl.Limiter("192.168.2.1")
	if l2 == nil || l2.Limit() != 30 {
		t.Errorf("Limit() = %v, want 30 (CIDR for non-exact match)", l2.Limit())
	}
}
