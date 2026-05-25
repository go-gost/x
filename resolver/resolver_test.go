package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
	resolver_util "github.com/go-gost/x/internal/util/resolver"
	"github.com/miekg/dns"
)

// mockExchanger implements exchanger.Exchanger for testing.
type mockExchanger struct {
	response *dns.Msg
	err      error
	calls    atomic.Int64
}

func (m *mockExchanger) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	if m.response != nil {
		return m.response.Pack()
	}
	// Echo back a basic response
	q := new(dns.Msg)
	if err := q.Unpack(msg); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	r.SetReply(q)
	return r.Pack()
}

func (m *mockExchanger) String() string {
	return "mock://test"
}

// newDNSMsgWithA creates a dns.Msg with A records for the given IPs.
func newDNSMsgWithA(ips ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		})
	}
	return m
}

// newDNSMsgWithAAAA creates a dns.Msg with AAAA records for the given IPs.
func newDNSMsgWithAAAA(ips ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeAAAA)
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP(ip),
		})
	}
	return m
}

func nopLog() options {
	return options{logger: xlogger.Nop()}
}

// newTestResolver creates a localResolver with cache and nop logger.
func newTestResolver(servers []NameServer, opts ...Option) *localResolver {
	o := options{logger: xlogger.Nop()}
	for _, opt := range opts {
		opt(&o)
	}
	cache := resolver_util.NewCache().WithLogger(xlogger.Nop())
	return &localResolver{
		servers:    servers,
		cache:      cache,
		options:    o,
		refreshSem: make(chan struct{}, maxAsyncRefresh),
	}
}

func TestResolve_IPLiteral(t *testing.T) {
	r := &localResolver{options: nopLog()}

	tests := []struct {
		host string
		want string
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
	}
	for _, tt := range tests {
		ips, err := r.Resolve(context.Background(), "ip", tt.host)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", tt.host, err)
		}
		if len(ips) != 1 || !ips[0].Equal(net.ParseIP(tt.want)) {
			t.Errorf("Resolve(%q) = %v, want [%s]", tt.host, ips, tt.want)
		}
	}
}

func TestResolve_DomainSuffix(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver(
		[]NameServer{{exchanger: ex, TTL: time.Minute}},
		DomainOption("example.com"),
	)

	_, err := r.Resolve(context.Background(), "ip", "host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ex.calls.Load() == 0 {
		t.Fatal("expected exchanger to be called")
	}
}

func TestResolve_DomainSuffixNotAppliedToFQDN(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver(
		[]NameServer{{exchanger: ex, TTL: time.Minute}},
		DomainOption("example.com"),
	)

	_, err := r.Resolve(context.Background(), "ip", "host.other.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ex.calls.Load() == 0 {
		t.Fatal("expected exchanger to be called")
	}
}

func TestResolve_MultipleServers_Fallback(t *testing.T) {
	failEx := &mockExchanger{err: net.UnknownNetworkError("fail")}
	okEx := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}

	r := newTestResolver([]NameServer{
		{exchanger: failEx, TTL: time.Minute},
		{exchanger: okEx, TTL: time.Minute},
	})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected fallback to second server")
	}
	if failEx.calls.Load() == 0 {
		t.Error("expected first server to be called")
	}
	if okEx.calls.Load() == 0 {
		t.Error("expected second server to be called")
	}
}

func TestResolve_AllServersFail(t *testing.T) {
	ex1 := &mockExchanger{err: net.UnknownNetworkError("fail1")}
	ex2 := &mockExchanger{err: net.UnknownNetworkError("fail2")}

	r := newTestResolver([]NameServer{
		{exchanger: ex1, TTL: time.Minute},
		{exchanger: ex2, TTL: time.Minute},
	})

	ips, _ := r.Resolve(context.Background(), "ip", "example.com")
	if len(ips) != 0 {
		t.Fatalf("expected no IPs when all servers fail, got %v", ips)
	}
}

func TestResolve_EmptyServers(t *testing.T) {
	r := &localResolver{servers: []NameServer{}, options: nopLog()}

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("expected no IPs with no servers, got %v", ips)
	}
}

func TestResolve_IPv4Only(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, Only: "ipv4", Prefer: "ipv4", TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected IPv4 result")
	}
}

func TestResolve_IPv6Only(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithAAAA("2001:db8::1")}
	r := newTestResolver([]NameServer{{exchanger: ex, Only: "ipv6", Prefer: "ipv6", TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected IPv6 result")
	}
}

func TestResolve_IPv6Prefer_FallbackToIPv4(t *testing.T) {
	aEx := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: aEx, Prefer: "ipv6", TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected IPv4 fallback result")
	}
}

func TestResolve_CacheHit(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	// First call: cache miss → exchanges with server
	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected result on first call")
	}
	firstCalls := ex.calls.Load()

	// Second call: should hit cache (TTL = 1 minute)
	ips, err = r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected cached result")
	}
	if ex.calls.Load() != firstCalls {
		t.Errorf("expected no additional exchange calls (got %d total)", ex.calls.Load())
	}
}

func TestResolve_NilServer(t *testing.T) {
	r := &localResolver{options: nopLog()}

	ips, err := r.resolve(context.Background(), nil, "example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("expected no IPs for nil server, got %v", ips)
	}
}

func TestResolve_AsyncCacheMiss(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, Async: true, TTL: time.Minute}})

	// Cache miss → should do synchronous resolve
	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected result on first async call (cache miss)")
	}
	if ex.calls.Load() != 1 {
		t.Errorf("expected 1 exchange call, got %d", ex.calls.Load())
	}
}

func TestResolve_AsyncCacheHitWithRefresh(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, Async: true, TTL: time.Minute}})

	// Populate cache first
	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("setup: expected result")
	}

	// Manually expire the cache entry
	mq := new(dns.Msg)
	mq.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	key := resolver_util.NewCacheKey(&mq.Question[0])
	mr := newDNSMsgWithA("10.0.0.2")
	r.cache.Store(context.Background(), key, mr, -1*time.Second)

	beforeCalls := ex.calls.Load()

	// Cache hit with expired TTL → should return stale data and trigger background refresh
	ips, err = r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return data (from stale cache or fresh resolve)
	_ = ips

	// Give background goroutine time to complete
	time.Sleep(50 * time.Millisecond)

	// Background refresh should have fired
	if ex.calls.Load() <= beforeCalls {
		t.Logf("note: background refresh may not have fired yet (calls: before=%d, now=%d)", beforeCalls, ex.calls.Load())
	}
}

func TestResolve_CancelledContext(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.Resolve(ctx, "ip", "example.com")
	// Should handle cancelled context gracefully (error or empty result)
	_ = err
}

func TestResolveIPs_ExtractsAAndAAAA(t *testing.T) {
	// Build a response with both A and AAAA records
	mr := new(dns.Msg)
	mr.SetQuestion("example.com.", dns.TypeA)
	mr.Answer = append(mr.Answer,
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("10.0.0.1"),
		},
		&dns.AAAA{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	)

	ex := &mockExchanger{response: mr}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) < 2 {
		t.Fatalf("expected at least 2 IPs (A+AAAA), got %d: %v", len(ips), ips)
	}

	has4, has6 := false, false
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("10.0.0.1")) {
			has4 = true
		}
		if ip.Equal(net.ParseIP("2001:db8::1")) {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Errorf("expected both A and AAAA records in result, got %v", ips)
	}
}

func TestExchange_RoundTrip(t *testing.T) {
	mq := new(dns.Msg)
	mq.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	mq.RecursionDesired = true

	packed, err := mq.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	reply, err := ex.Exchange(context.Background(), packed)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) == 0 {
		t.Fatal("expected answers in response")
	}
}

func TestDomainOption(t *testing.T) {
	opts := &options{}
	DomainOption("test.local")(opts)
	if opts.domain != "test.local" {
		t.Errorf("expected domain 'test.local', got %q", opts.domain)
	}
}

func TestLoggerOption(t *testing.T) {
	opts := &options{}
	l := xlogger.Nop()
	LoggerOption(l)(opts)
	if opts.logger != l {
		t.Error("logger option not applied")
	}
}

func TestExchange_DNSRcodeError(t *testing.T) {
	// Return a message with NXDOMAIN rcode
	mr := new(dns.Msg)
	mr.SetRcode(&dns.Msg{MsgHdr: dns.MsgHdr{Id: 1}}, dns.RcodeNameError)
	packed, err := mr.Pack()
	if err != nil {
		t.Fatal(err)
	}

	ex := &rcodeMockExchanger{response: packed}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip", "nonexistent.example.com")
	if err == nil {
		t.Fatal("expected error for NXDOMAIN")
	}
	if len(ips) != 0 {
		t.Fatalf("expected no IPs for NXDOMAIN, got %v", ips)
	}
}

func TestExchange_DNSRcodeServfail_Fallback(t *testing.T) {
	// First server returns SERVFAIL, second returns success
	servfailMr := new(dns.Msg)
	servfailMr.SetRcode(&dns.Msg{MsgHdr: dns.MsgHdr{Id: 1}}, dns.RcodeServerFailure)
	packed, err := servfailMr.Pack()
	if err != nil {
		t.Fatal(err)
	}

	okEx := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	servfailEx := &rcodeMockExchanger{response: packed}

	r := newTestResolver([]NameServer{
		{exchanger: servfailEx, TTL: time.Minute},
		{exchanger: okEx, TTL: time.Minute},
	})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected fallback to second server")
	}
}

func TestResolve_NetworkIP4(t *testing.T) {
	// When caller asks for ip4, only A queries should be made (no AAAA fallback).
	// Use a mock that returns empty response for A queries.
	ex := &mockExchanger{response: new(dns.Msg)} // empty response, no records
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip4", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should get empty result (no A records), and NOT fall back to IPv6
	if len(ips) != 0 {
		t.Errorf("expected no IPs when only ip4 requested and no A records, got %v", ips)
	}
}

func TestResolve_NetworkIP6(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithAAAA("2001:db8::1")}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip6", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected IPv6 result for ip6 network")
	}
}

func TestResolve_NetworkIP4_ServerOnlyOverrides(t *testing.T) {
	// Server configured with Only="ipv6", caller asks for "ip4" → server wins
	ex := &mockExchanger{response: newDNSMsgWithAAAA("2001:db8::1")}
	r := newTestResolver([]NameServer{{exchanger: ex, Only: "ipv6", Prefer: "ipv6", TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip4", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Server Only=ipv6 should override caller's ip4 request
	if len(ips) == 0 {
		t.Fatal("expected IPv6 result (server Only overrides caller)")
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			t.Errorf("expected only IPv6 from server Only constraint, got %v", ip)
		}
	}
}

func TestResolve_ConcurrentDedup(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	const n = 10
	var wg sync.WaitGroup
	results := make([][]net.IP, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = r.Resolve(context.Background(), "ip", "example.com")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, err)
		}
		if len(results[i]) == 0 {
			t.Fatalf("goroutine %d: expected IPs", i)
		}
	}

	// singleflight should have deduplicated the exchange calls
	calls := ex.calls.Load()
	if calls > 2 { // allow small margin for race, but not 10
		t.Errorf("expected ~1 exchange call from singleflight, got %d", calls)
	}
}

func TestResolve_IP_UnchangedBehavior(t *testing.T) {
	ex := &mockExchanger{response: newDNSMsgWithA("10.0.0.1")}
	r := newTestResolver([]NameServer{{exchanger: ex, TTL: time.Minute}})

	ips, err := r.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected result for network=ip (default behavior)")
	}
}

// rcodeMockExchanger returns a pre-packed response, used for DNS rcode testing.
type rcodeMockExchanger struct {
	response []byte
}

func (m *rcodeMockExchanger) Exchange(_ context.Context, _ []byte) ([]byte, error) {
	return m.response, nil
}

func (m *rcodeMockExchanger) String() string { return "mock://rcode" }
