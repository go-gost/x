package traffic

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/limiter"
	traffic "github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
	"github.com/patrickmn/go-cache"
	"github.com/yl2chen/cidranger"
)

// --- test helpers ---

func newTestTrafficLimiter(limits ...string) *trafficLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	lim := &trafficLimiter{
		cidrGenerators: cidranger.NewPCTrieRanger(),
		connInLimits:   cache.New(defaultExpiration, cleanupInterval),
		connOutLimits:  cache.New(defaultExpiration, cleanupInterval),
		inLimits:       cache.New(defaultExpiration, cleanupInterval),
		outLimits:      cache.New(defaultExpiration, cleanupInterval),
		options:        options{limits: limits},
		cancelFunc:     cancel,
		logger:         xlogger.Nop(),
	}
	_ = lim.reload(ctx)
	return lim
}

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

type errorLoader struct{}

func (e *errorLoader) Load(ctx context.Context) (io.Reader, error) { return nil, io.ErrUnexpectedEOF }
func (e *errorLoader) Close() error                                { return nil }

// --- parsing tests ---

func TestParseLine(t *testing.T) {
	l := newTestTrafficLimiter()
	tests := []struct {
		input, expected string
	}{
		{"192.168.1.1 100B 200B", "192.168.1.1 100B 200B"},
		{"  192.168.1.1 100B 200B  ", "192.168.1.1 100B 200B"},
		{"192.168.1.1 100B 200B # comment", "192.168.1.1 100B 200B"},
		{"# only comment", ""},
		{"   # indented comment", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := l.parseLine(tt.input)
		if got != tt.expected {
			t.Errorf("parseLine(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseLimit(t *testing.T) {
	l := newTestTrafficLimiter()
	tests := []struct {
		input   string
		key     string
		in, out int
	}{
		{"192.168.1.1 100B 200B", "192.168.1.1", 100, 200},
		{"192.168.1.1\t100B\t200B", "192.168.1.1", 100, 200},
		{"$ 1KB", "$", 1024, 0},
		{"$$ 500B", "$$", 500, 0},
		{"10.0.0.0/8 1KB 2KB", "10.0.0.0/8", 1024, 2048},
		{"key   100B   200B", "key", 100, 200},
		{"key 1MB", "key", 1048576, 0},
		{"key 512KB 1MB", "key", 524288, 1048576},
		{"key_only", "", 0, 0},
		{"", "", 0, 0},
		{"key invalid_bytes", "key", 0, 0},
	}
	for _, tt := range tests {
		key, in, out, burst := l.parseLimit(tt.input)
		if burst != 0 {
			t.Errorf("parseLimit(%q) unexpected burst: %d", tt.input, burst)
		}
		if key != tt.key || in != tt.in || out != tt.out {
			t.Errorf("parseLimit(%q) = (%q, %d, %d), want (%q, %d, %d)",
				tt.input, key, in, out, tt.key, tt.in, tt.out)
		}
	}
}

func TestParsePatterns(t *testing.T) {
	l := newTestTrafficLimiter()
	r := strings.NewReader("192.168.1.1 100B\n# comment\n\n10.0.0.1 200B\n")
	patterns, err := l.parsePatterns(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d: %v", len(patterns), patterns)
	}
	if patterns[0] != "192.168.1.1 100B" {
		t.Errorf("patterns[0] = %q", patterns[0])
	}
	if patterns[1] != "10.0.0.1 200B" {
		t.Errorf("patterns[1] = %q", patterns[1])
	}
}

func TestParsePatterns_NilReader(t *testing.T) {
	l := newTestTrafficLimiter()
	patterns, err := l.parsePatterns(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 0 {
		t.Fatalf("expected 0 patterns, got %d", len(patterns))
	}
}

// --- load tests ---

func TestLoad_NoLoaders(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v, ok := values["$"]
	if !ok {
		t.Fatal("expected $ key in loaded values")
	}
	if v.in != 100 || v.out != 0 {
		t.Fatalf("expected in=100 out=0, got in=%d out=%d", v.in, v.out)
	}
}

func TestLoad_FileLister(t *testing.T) {
	l := newTestTrafficLimiter()
	l.options.fileLoader = &fakeLoader{data: "$ 50B\n192.168.1.1 200B 300B"}
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := values["$"]; v.in != 50 {
		t.Fatalf("expected $ in=50, got %d", v.in)
	}
	v := values["192.168.1.1"]
	if v.in != 200 || v.out != 300 {
		t.Fatalf("expected in=200 out=300, got in=%d out=%d", v.in, v.out)
	}
}

func TestLoad_FileLoader(t *testing.T) {
	l := newTestTrafficLimiter()
	l.options.fileLoader = &fakeLoader{data: "$ 30B"}
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := values["$"]; v.in != 30 {
		t.Fatalf("expected $ in=30, got %d", v.in)
	}
}

func TestLoad_RedisLoader(t *testing.T) {
	l := newTestTrafficLimiter()
	l.options.redisLoader = &fakeLoader{data: "$ 40B"}
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := values["$"]; v.in != 40 {
		t.Fatalf("expected $ in=40, got %d", v.in)
	}
}

func TestLoad_HTTPLoader(t *testing.T) {
	l := newTestTrafficLimiter()
	l.options.httpLoader = &fakeLoader{data: "$ 35B"}
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := values["$"]; v.in != 35 {
		t.Fatalf("expected $ in=35, got %d", v.in)
	}
}

func TestLoad_ErrorLoader(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	l.options.fileLoader = &errorLoader{}
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal("error loader should not propagate error")
	}
	if v := values["$"]; v.in != 100 {
		t.Fatalf("expected $ in=100 from static limits, got %d", v.in)
	}
}

func TestLoad_MergesLoaders(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	l.options.fileLoader = &fakeLoader{data: "192.168.1.1 50B"}
	l.options.httpLoader = &fakeLoader{data: "$ 200B"}
	values, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := values["$"]; v.in != 200 {
		t.Fatalf("expected $ in=200 (HTTP overrides static), got %d", v.in)
	}
	if v := values["192.168.1.1"]; v.in != 50 {
		t.Fatalf("expected 192.168.1.1 in=50, got %d", v.in)
	}
}

// --- In/Out tests ---

func TestIn_ServiceScope(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	v := l.In(context.Background(), "any-key", limiter.ScopeOption(limiter.ScopeService))
	if v == nil {
		t.Fatal("expected service-level In limiter")
	}
	if v.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", v.Limit())
	}
}

func TestIn_ClientScope(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	v := l.In(context.Background(), "any-key", limiter.ScopeOption(limiter.ScopeClient))
	if v != nil {
		t.Fatal("ScopeClient should return nil")
	}
}

func TestIn_ConnScope_GeneratesLimiter(t *testing.T) {
	l := newTestTrafficLimiter("$$ 100B")
	v := l.In(context.Background(), "10.0.0.1:12345")
	if v == nil {
		t.Fatal("expected conn-level In limiter")
	}
	if v.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", v.Limit())
	}
}

func TestIn_ConnScope_CachedResult(t *testing.T) {
	l := newTestTrafficLimiter("$$ 100B")
	v1 := l.In(context.Background(), "10.0.0.1:12345")
	v2 := l.In(context.Background(), "10.0.0.1:12345")
	// Both should have the correct limit (cached limiter reused in group).
	if v1 == nil || v2 == nil {
		t.Fatal("limiters should not be nil")
	}
	if v1.Limit() != 100 || v2.Limit() != 100 {
		t.Fatalf("expected limit 100, got v1=%d v2=%d", v1.Limit(), v2.Limit())
	}
	// The cache entry should exist for the key.
	if _, ok := l.connInLimits.Get("10.0.0.1:12345"); !ok {
		t.Fatal("expected cached conn-level In limiter")
	}
}

func TestIn_IPMatch(t *testing.T) {
	l := newTestTrafficLimiter("192.168.1.1 100B")
	v := l.In(context.Background(), "192.168.1.1:12345")
	if v == nil {
		t.Fatal("expected IP-level In limiter")
	}
	if v.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", v.Limit())
	}
}

func TestIn_CIDRMatch(t *testing.T) {
	l := newTestTrafficLimiter("10.0.0.0/8 100B")
	v := l.In(context.Background(), "10.0.0.1:12345")
	if v == nil {
		t.Fatal("expected CIDR-level In limiter")
	}
	if v.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", v.Limit())
	}
}

func TestIn_CIDRNoMatch(t *testing.T) {
	l := newTestTrafficLimiter("10.0.0.0/8 100B")
	v := l.In(context.Background(), "192.168.1.1:12345")
	if v != nil {
		t.Fatalf("CIDR should not match different IP range, got limit %d", v.Limit())
	}
}

func TestIn_IPTakesPrecedence(t *testing.T) {
	l := newTestTrafficLimiter("10.0.0.0/8 5B", "10.0.0.1 2B")
	v := l.In(context.Background(), "10.0.0.1:12345")
	if v == nil {
		t.Fatal("expected limiter for exact IP + CIDR")
	}
	if v.Limit() != 2 {
		t.Fatalf("exact IP should take precedence, expected limit 2, got %d", v.Limit())
	}
}

func TestOut_ServiceScope(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B 100B")
	v := l.Out(context.Background(), "any-key", limiter.ScopeOption(limiter.ScopeService))
	if v == nil {
		t.Fatal("expected service-level Out limiter")
	}
	if v.Limit() != 100 {
		t.Fatalf("expected limit 100, got %d", v.Limit())
	}
}

func TestOut_ClientScope(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	v := l.Out(context.Background(), "any-key", limiter.ScopeOption(limiter.ScopeClient))
	if v != nil {
		t.Fatal("ScopeClient Out should return nil")
	}
}

func TestOut_ConnScope(t *testing.T) {
	l := newTestTrafficLimiter("$$ 200B 200B")
	v := l.Out(context.Background(), "10.0.0.1:12345")
	if v == nil {
		t.Fatal("expected conn-level Out limiter")
	}
	if v.Limit() != 200 {
		t.Fatalf("expected limit 200, got %d", v.Limit())
	}
}

// --- reload tests ---

func TestReload_ServiceLimit(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("$ 100B")
	v1 := l.In(ctx, "x", limiter.ScopeOption(limiter.ScopeService))
	if v1.Limit() != 100 {
		t.Fatalf("expected 100, got %d", v1.Limit())
	}

	l.options.limits = []string{"$ 200B"}
	_ = l.reload(ctx)

	v2 := l.In(ctx, "x", limiter.ScopeOption(limiter.ScopeService))
	if v2.Limit() != 200 {
		t.Fatalf("expected 200 after reload, got %d", v2.Limit())
	}
}

func TestReload_ConnLimit(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("$$ 100B")
	v1 := l.In(ctx, "10.0.0.1:12345")
	if v1.Limit() != 100 {
		t.Fatalf("expected 100, got %d", v1.Limit())
	}

	l.options.limits = []string{"$$ 200B"}
	_ = l.reload(ctx)

	v2 := l.In(ctx, "10.0.0.2:12345")
	if v2.Limit() != 200 {
		t.Fatalf("expected 200 after reload, got %d", v2.Limit())
	}
}

func TestReload_ConnLimit_UpdatesExisting(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("$$ 100B")
	v1 := l.In(ctx, "10.0.0.1:12345")
	if v1.Limit() != 100 {
		t.Fatalf("expected 100, got %d", v1.Limit())
	}

	l.options.limits = []string{"$$ 200B"}
	_ = l.reload(ctx)

	// Same cached limiter should have been updated in-place.
	if v1.Limit() != 200 {
		t.Fatalf("existing cached limiter should be updated to 200, got %d", v1.Limit())
	}
}

func TestReload_IPLimit(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("192.168.1.1 100B")
	v := l.In(ctx, "192.168.1.1:12345")
	if v.Limit() != 100 {
		t.Fatalf("expected 100, got %d", v.Limit())
	}

	l.options.limits = []string{"192.168.1.1 200B"}
	_ = l.reload(ctx)

	if v.Limit() != 200 {
		t.Fatalf("expected 200 after reload, got %d", v.Limit())
	}
}

func TestReload_CIDRLimit(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("10.0.0.0/8 100B")
	v := l.In(ctx, "10.0.0.1:12345")
	if v.Limit() != 100 {
		t.Fatalf("expected 100, got %d", v.Limit())
	}

	l.options.limits = []string{"10.0.0.0/8 200B"}
	_ = l.reload(ctx)

	if v.Limit() != 200 {
		t.Fatalf("expected 200 after CIDR reload, got %d", v.Limit())
	}
}

func TestReload_RemovesObsoleteLimit(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("192.168.1.1 100B")
	_ = l.In(ctx, "192.168.1.1:12345")

	l.options.limits = nil
	_ = l.reload(ctx)

	v := l.In(ctx, "192.168.1.1:12345")
	if v != nil {
		t.Fatalf("obsolete IP limit should be removed, got limit %d", v.Limit())
	}
}

func TestReload_ClearsConnCacheWhenRemoved(t *testing.T) {
	ctx := context.Background()
	l := newTestTrafficLimiter("$$ 100B")
	_ = l.In(ctx, "10.0.0.1:12345")

	l.options.limits = []string{"$$ 0B"}
	_ = l.reload(ctx)

	v := l.In(ctx, "10.0.0.2:12345")
	if v != nil {
		t.Fatalf("conn cache should be flushed, got limiter with limit %d", v.Limit())
	}
}

// --- close tests ---

func TestClose(t *testing.T) {
	fl := &fakeLoader{}
	rl := &fakeLoader{}
	hl := &fakeLoader{}

	l := newTestTrafficLimiter()
	l.options.fileLoader = fl
	l.options.redisLoader = rl
	l.options.httpLoader = hl

	l.Close()

	if !fl.closed {
		t.Error("fileLoader should be closed")
	}
	if !rl.closed {
		t.Error("redisLoader should be closed")
	}
	if !hl.closed {
		t.Error("httpLoader should be closed")
	}
}

func TestClose_Idempotent(t *testing.T) {
	l := newTestTrafficLimiter()
	l.Close()
	l.Close()
}

func TestClose_NilLoaders(t *testing.T) {
	l := newTestTrafficLimiter()
	if err := l.Close(); err != nil {
		t.Fatal("Close with nil loaders should return nil error")
	}
}

// --- lifecycle tests ---

func TestPeriodReload_ZeroPeriod(t *testing.T) {
	l := newTestTrafficLimiter()
	l.options.period = 0

	ctx := context.Background()
	err := l.periodReload(ctx)
	if err != nil {
		t.Fatalf("zero period should return nil, got %v", err)
	}
}

func TestPeriodReload_ContextCancel(t *testing.T) {
	l := newTestTrafficLimiter("$ 100B")
	l.options.period = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := l.periodReload(ctx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNewTrafficLimiter_Defaults(t *testing.T) {
	lim := NewTrafficLimiter()
	if lim == nil {
		t.Fatal("NewTrafficLimiter should not return nil")
	}
	if closer, ok := lim.(io.Closer); ok {
		closer.Close()
	}
}

// --- concurrency ---

func TestIn_ConcurrentAccess(t *testing.T) {
	l := newTestTrafficLimiter("$$ 1KB", "192.168.1.1 500B", "10.0.0.0/8 200B", "$ 100B")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = l.In(ctx, "10.0.0.1:12345")
			_ = l.In(ctx, "192.168.1.1:8080")
			_ = l.Out(ctx, "10.0.0.2:9090")
		}(i)
	}
	wg.Wait()
}

// --- interface compliance ---

var (
	_ traffic.TrafficLimiter = (*trafficLimiter)(nil)
	_ io.Closer             = (*trafficLimiter)(nil)
	_ loader.Loader         = (*fakeLoader)(nil)
	_ loader.Lister         = (*fakeLoader)(nil)
)
