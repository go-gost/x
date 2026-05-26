package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	resolver_util "github.com/go-gost/x/internal/util/resolver"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/resolver/exchanger"
	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockExchanger struct {
	exchangeFn func(ctx context.Context, msg []byte) ([]byte, error)
	addr       string
}

func (m *mockExchanger) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	if m.exchangeFn != nil {
		return m.exchangeFn(ctx, msg)
	}
	return nil, nil
}

func (m *mockExchanger) String() string { return m.addr }

// mockHop implements hop.Hop and hop.NodeList.
type mockHop struct {
	selectFn func(ctx context.Context, opts ...hop.SelectOption) *chain.Node
	nodes    []*chain.Node
}

func (m *mockHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if m.selectFn != nil {
		return m.selectFn(ctx, opts...)
	}
	return nil
}

func (m *mockHop) Nodes() []*chain.Node { return m.nodes }

type mockHostMapper struct {
	lookupFn func(ctx context.Context, network, host string) ([]net.IP, bool)
}

func (m *mockHostMapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	if m.lookupFn != nil {
		return m.lookupFn(ctx, network, host)
	}
	return nil, false
}

type mockBypass struct {
	containsFn func(ctx context.Context, network, addr string) bool
	whitelist  bool
}

func (m *mockBypass) IsWhitelist() bool { return m.whitelist }

func (m *mockBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if m.containsFn != nil {
		return m.containsFn(ctx, network, addr)
	}
	return false
}

type mockRateLimiter struct {
	limiterFn func(key string) rate.Limiter
}

func (m *mockRateLimiter) Limiter(key string) rate.Limiter {
	if m.limiterFn != nil {
		return m.limiterFn(key)
	}
	return nil
}

type mockLimiter struct {
	allowFn func(n int) bool
	limit   float64
}

func (m *mockLimiter) Allow(n int) bool {
	if m.allowFn != nil {
		return m.allowFn(n)
	}
	return true
}

func (m *mockLimiter) Limit() float64 { return m.limit }

// mockRouter implements chain.Router.
type mockRouter struct {
	opts *chain.RouterOptions
}

func (m *mockRouter) Options() *chain.RouterOptions { return m.opts }
func (m *mockRouter) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	return nil, nil
}
func (m *mockRouter) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nopLog() logger.Logger { return xlogger.Nop() }

func newRecObj() *xrecorder.HandlerRecorderObject {
	return &xrecorder.HandlerRecorderObject{Time: time.Now()}
}

func newTestHandler(opts ...handler.Option) *dnsHandler {
	options := handler.Options{
		Logger: nopLog(),
		Router: &mockRouter{opts: &chain.RouterOptions{}},
	}
	for _, opt := range opts {
		opt(&options)
	}
	return &dnsHandler{
		options:    options,
		exchangers: make(map[string]exchanger.Exchanger),
	}
}

func newInitdHandler(opts ...handler.Option) *dnsHandler {
	h := newTestHandler(opts...)
	_ = h.Init(xmd.NewMetadata(nil))
	return h
}

// packDNSQuery creates a raw DNS query for the given name/type.
func packDNSQuery(name string, qtype uint16) []byte {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	b, _ := m.Pack()
	return b
}

func mustNewRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

// stringConn is a net.Conn backed by bytes.Buffers for testing.
type stringConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	local    net.Addr
	remote   net.Addr
}

func newStringConn(data []byte) *stringConn {
	return &stringConn{
		readBuf:  bytes.NewBuffer(data),
		writeBuf: &bytes.Buffer{},
		local:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote:   &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
	}
}

func (c *stringConn) Read(b []byte) (int, error)               { return c.readBuf.Read(b) }
func (c *stringConn) Write(b []byte) (int, error)              { return c.writeBuf.Write(b) }
func (c *stringConn) Close() error                              { return nil }
func (c *stringConn) LocalAddr() net.Addr                       { return c.local }
func (c *stringConn) RemoteAddr() net.Addr                      { return c.remote }
func (c *stringConn) SetDeadline(t time.Time) error             { return nil }
func (c *stringConn) SetReadDeadline(t time.Time) error         { return nil }
func (c *stringConn) SetWriteDeadline(t time.Time) error        { return nil }

// slowConn blocks on Read for the given duration.
type slowConn struct{ readDelay time.Duration }

func (c *slowConn) Read(b []byte) (int, error)  { time.Sleep(c.readDelay); return 0, errors.New("timeout") }
func (c *slowConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *slowConn) Close() error                { return nil }
func (c *slowConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (c *slowConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
}
func (c *slowConn) SetDeadline(t time.Time) error             { return nil }
func (c *slowConn) SetReadDeadline(t time.Time) error         { return nil }
func (c *slowConn) SetWriteDeadline(t time.Time) error        { return nil }

// ---------------------------------------------------------------------------
// Tests: parseMetadata
// ---------------------------------------------------------------------------

func TestParseMetadata_Defaults(t *testing.T) {
	h := newTestHandler()
	if err := h.parseMetadata(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if h.md.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", h.md.timeout, defaultTimeout)
	}
	if h.md.bufferSize != defaultBufferSize {
		t.Errorf("bufferSize = %d, want %d", h.md.bufferSize, defaultBufferSize)
	}
	if h.md.async {
		t.Error("async should be false by default")
	}
	if h.md.readTimeout != 0 {
		t.Errorf("readTimeout = %v, want 0", h.md.readTimeout)
	}
	if h.md.ttl != 0 {
		t.Errorf("ttl = %v, want 0", h.md.ttl)
	}
}

func TestParseMetadata_AllFields(t *testing.T) {
	h := newTestHandler()
	err := h.parseMetadata(xmd.NewMetadata(map[string]any{
		"readTimeout": "10s",
		"ttl":         "30s",
		"timeout":     "3s",
		"clientIP":    "1.2.3.4",
		"dns":         "udp://8.8.8.8:53, tcp://1.1.1.1:53",
		"bufferSize":  2048,
		"async":       true,
	}))
	if err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if h.md.readTimeout != 10*time.Second {
		t.Errorf("readTimeout = %v, want 10s", h.md.readTimeout)
	}
	if h.md.ttl != 30*time.Second {
		t.Errorf("ttl = %v, want 30s", h.md.ttl)
	}
	if h.md.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", h.md.timeout)
	}
	if !h.md.clientIP.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("clientIP = %v, want 1.2.3.4", h.md.clientIP)
	}
	if h.md.bufferSize != 2048 {
		t.Errorf("bufferSize = %d, want 2048", h.md.bufferSize)
	}
	if !h.md.async {
		t.Error("async should be true")
	}
	if len(h.md.dns) != 2 {
		t.Fatalf("len(dns) = %d, want 2", len(h.md.dns))
	}
	if h.md.dns[0] != "udp://8.8.8.8:53" {
		t.Errorf("dns[0] = %q, want %q", h.md.dns[0], "udp://8.8.8.8:53")
	}
	if h.md.dns[1] != "tcp://1.1.1.1:53" {
		t.Errorf("dns[1] = %q, want %q", h.md.dns[1], "tcp://1.1.1.1:53")
	}
}

func TestParseMetadata_EmptyDNS(t *testing.T) {
	h := newTestHandler()
	if err := h.parseMetadata(xmd.NewMetadata(map[string]any{"dns": ""})); err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if len(h.md.dns) != 0 {
		t.Errorf("len(dns) = %d, want 0", len(h.md.dns))
	}
}

func TestParseMetadata_TimeoutAsInt(t *testing.T) {
	h := newTestHandler()
	if err := h.parseMetadata(xmd.NewMetadata(map[string]any{"timeout": 10})); err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if h.md.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", h.md.timeout)
	}
}

// ---------------------------------------------------------------------------
// Tests: NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler(handler.LoggerOption(nopLog()))
	if _, ok := h.(*dnsHandler); !ok {
		t.Error("NewHandler should return *dnsHandler")
	}
}

// ---------------------------------------------------------------------------
// Tests: Init
// ---------------------------------------------------------------------------

func TestInit_DefaultExchanger(t *testing.T) {
	h := newTestHandler()
	if err := h.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(h.exchangers) != 1 {
		t.Fatalf("len(exchangers) = %d, want 1", len(h.exchangers))
	}
	if _, ok := h.exchangers["default"]; !ok {
		t.Error("expected 'default' exchanger")
	}
}

func TestInit_WithHopNodes(t *testing.T) {
	h := newTestHandler()
	h.hop = &mockHop{nodes: []*chain.Node{
		chain.NewNode("ns1", "udp://8.8.8.8:53"),
		chain.NewNode("ns2", "tcp://1.1.1.1:53"),
	}}
	if err := h.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(h.exchangers) != 2 {
		t.Errorf("len(exchangers) = %d, want 2", len(h.exchangers))
	}
	if _, ok := h.exchangers["ns1"]; !ok {
		t.Error("expected 'ns1' exchanger")
	}
	if _, ok := h.exchangers["ns2"]; !ok {
		t.Error("expected 'ns2' exchanger")
	}
}

func TestInit_SkipsEmptyAddr(t *testing.T) {
	h := newTestHandler()
	h.hop = &mockHop{nodes: []*chain.Node{
		chain.NewNode("empty", ""),
		chain.NewNode("spaces", "  "),
		chain.NewNode("valid", "udp://8.8.8.8:53"),
	}}
	if err := h.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(h.exchangers) != 1 {
		t.Errorf("len(exchangers) = %d, want 1", len(h.exchangers))
	}
	if _, ok := h.exchangers["valid"]; !ok {
		t.Error("expected 'valid' exchanger")
	}
}

func TestInit_MetadataDNS(t *testing.T) {
	h := newTestHandler()
	if err := h.Init(xmd.NewMetadata(map[string]any{"dns": "udp://8.8.8.8:53"})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(h.exchangers) != 1 {
		t.Errorf("len(exchangers) = %d, want 1", len(h.exchangers))
	}
	if _, ok := h.exchangers["target-0"]; !ok {
		t.Error("expected 'target-0' exchanger")
	}
}

func TestInit_HostMapper(t *testing.T) {
	mapper := &mockHostMapper{}
	h := newTestHandler()
	h.options.Router = &mockRouter{
		opts: &chain.RouterOptions{HostMapper: mapper},
	}
	if err := h.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.hostMapper != hosts.HostMapper(mapper) {
		t.Error("hostMapper not set from router options")
	}
}

// ---------------------------------------------------------------------------
// Tests: Forward
// ---------------------------------------------------------------------------

func TestForward(t *testing.T) {
	h := newInitdHandler()
	newHop := &mockHop{}
	h.Forward(newHop)
	if h.hop != hop.Hop(newHop) {
		t.Error("Forward did not set hop")
	}
}

// ---------------------------------------------------------------------------
// Tests: checkRateLimit
// ---------------------------------------------------------------------------

func TestCheckRateLimit_NilLimiter(t *testing.T) {
	h := newInitdHandler()
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("should allow when no rate limiter configured")
	}
}

func TestCheckRateLimit_Allowed(t *testing.T) {
	h := newInitdHandler()
	h.options.RateLimiter = &mockRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &mockLimiter{allowFn: func(n int) bool { return true }}
		},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("should allow when limiter permits")
	}
}

func TestCheckRateLimit_Blocked(t *testing.T) {
	h := newInitdHandler()
	h.options.RateLimiter = &mockRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &mockLimiter{allowFn: func(n int) bool { return false }}
		},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	if h.checkRateLimit(addr) {
		t.Error("should block when limiter denies")
	}
}

func TestCheckRateLimit_NoLimiterForKey(t *testing.T) {
	h := newInitdHandler()
	h.options.RateLimiter = &mockRateLimiter{
		limiterFn: func(key string) rate.Limiter { return nil },
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("should allow when no limiter for key")
	}
}

// ---------------------------------------------------------------------------
// Tests: selectExchanger
// ---------------------------------------------------------------------------

func TestSelectExchanger_NilHop(t *testing.T) {
	h := newInitdHandler()
	h.hop = nil
	if ex := h.selectExchanger(context.Background(), "example.com"); ex != nil {
		t.Error("expected nil for nil hop")
	}
}

func TestSelectExchanger_NoNode(t *testing.T) {
	h := newInitdHandler()
	h.hop = &mockHop{}
	if ex := h.selectExchanger(context.Background(), "example.com"); ex != nil {
		t.Error("expected nil when hop returns no node")
	}
}

func TestSelectExchanger_FoundNode(t *testing.T) {
	mockEx := &mockExchanger{addr: "udp://8.8.8.8:53"}
	h := newInitdHandler()
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx
	if ex := h.selectExchanger(context.Background(), "example.com"); ex != mockEx {
		t.Error("expected mock exchanger")
	}
}

func TestSelectExchanger_NodeNotInExchangers(t *testing.T) {
	h := newInitdHandler()
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("unknown", "udp://8.8.8.8:53")
		},
	}
	if ex := h.selectExchanger(context.Background(), "example.com"); ex != nil {
		t.Error("expected nil for unknown node")
	}
}

// ---------------------------------------------------------------------------
// Tests: lookupHosts
// ---------------------------------------------------------------------------

func TestLookupHosts_NilMapper(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = nil
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if mr := h.lookupHosts(context.Background(), q, nopLog()); mr != nil {
		t.Error("expected nil for nil mapper")
	}
}

func TestLookupHosts_NonINETClass(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = &mockHostMapper{}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Question[0].Qclass = dns.ClassCHAOS
	if mr := h.lookupHosts(context.Background(), q, nopLog()); mr != nil {
		t.Error("expected nil for non-INET class")
	}
}

func TestLookupHosts_UnsupportedType(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = &mockHostMapper{}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeMX)
	if mr := h.lookupHosts(context.Background(), q, nopLog()); mr != nil {
		t.Error("expected nil for unsupported type")
	}
}

func TestLookupHosts_ARecord(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = &mockHostMapper{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, bool) {
			if network != "ip4" {
				t.Errorf("network = %q, want %q", network, "ip4")
			}
			if host != "example.com" {
				t.Errorf("host = %q, want %q", host, "example.com")
			}
			return []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")}, true
		},
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	mr := h.lookupHosts(context.Background(), q, nopLog())
	if mr == nil {
		t.Fatal("expected non-nil response")
	}
	if len(mr.Answer) != 2 {
		t.Fatalf("len(Answer) = %d, want 2", len(mr.Answer))
	}
	for _, rr := range mr.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			t.Fatal("expected A record")
		}
		if a.Hdr.Name != "example.com." {
			t.Errorf("Name = %q, want %q", a.Hdr.Name, "example.com.")
		}
	}
}

func TestLookupHosts_AAAARecord(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = &mockHostMapper{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, bool) {
			if network != "ip6" {
				t.Errorf("network = %q, want %q", network, "ip6")
			}
			return []net.IP{net.ParseIP("::1")}, true
		},
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	mr := h.lookupHosts(context.Background(), q, nopLog())
	if mr == nil {
		t.Fatal("expected non-nil response")
	}
	if len(mr.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(mr.Answer))
	}
	aaaa, ok := mr.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatal("expected AAAA record")
	}
	if aaaa.Hdr.Name != "example.com." {
		t.Errorf("Name = %q, want %q", aaaa.Hdr.Name, "example.com.")
	}
}

func TestLookupHosts_EmptyResult(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = &mockHostMapper{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, bool) {
			return nil, false
		},
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if mr := h.lookupHosts(context.Background(), q, nopLog()); mr != nil {
		t.Error("expected nil for empty result")
	}
}

// ---------------------------------------------------------------------------
// Tests: exchange
// ---------------------------------------------------------------------------

func TestExchange_StoresInCache(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("cached.example.com.", dns.TypeA)
	query.Id = 42

	respMsg := query.Copy()
	respMsg.Answer = []dns.RR{mustNewRR("cached.example.com. 300 IN A 9.8.7.6")}
	respBytes, _ := respMsg.Pack()

	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			return respBytes, nil
		},
		addr: "udp://8.8.8.8:53",
	}

	h := newInitdHandler()
	h.md.bufferSize = defaultBufferSize
	h.md.ttl = 30 * time.Second

	mr, err := h.exchange(context.Background(), mockEx, query)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if mr == nil {
		t.Fatal("expected non-nil response")
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1", len(mr.Answer))
	}
}

func TestExchange_UpstreamError(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("fail.example.com.", dns.TypeA)

	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			return nil, errors.New("upstream unreachable")
		},
	}

	h := newInitdHandler()
	mr, err := h.exchange(context.Background(), mockEx, query)
	if err == nil {
		t.Fatal("expected error")
	}
	if mr != nil {
		t.Error("expected nil response on error")
	}
}

func TestExchange_InvalidResponse(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("bad.example.com.", dns.TypeA)

	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			return []byte("not a dns message"), nil
		},
	}

	h := newInitdHandler()
	mr, err := h.exchange(context.Background(), mockEx, query)
	if err == nil {
		t.Fatal("expected error for invalid DNS response")
	}
	if mr != nil {
		t.Error("expected nil response on error")
	}
}

// ---------------------------------------------------------------------------
// Tests: request
// ---------------------------------------------------------------------------

func TestRequest_EmptyQuestion(t *testing.T) {
	h := newInitdHandler()
	msg := new(dns.Msg)
	raw, _ := msg.Pack()
	_, err := h.request(context.Background(), raw, newRecObj(), nopLog())
	if err == nil {
		t.Fatal("expected error for empty question")
	}
	if got := err.Error(); got != "msg: empty question" {
		t.Errorf("error = %q, want %q", got, "msg: empty question")
	}
}

func TestRequest_InvalidMessage(t *testing.T) {
	h := newInitdHandler()
	_, err := h.request(context.Background(), []byte{0xFF, 0xFF, 0xFF}, newRecObj(), nopLog())
	if err == nil {
		t.Fatal("expected error for invalid DNS message")
	}
}

func TestRequest_Bypass(t *testing.T) {
	h := newInitdHandler()
	h.options.Bypass = &mockBypass{
		containsFn: func(ctx context.Context, network, addr string) bool {
			if network != "udp" {
				t.Errorf("network = %q, want %q", network, "udp")
			}
			if addr != "blocked.example.com" {
				t.Errorf("addr = %q, want %q", addr, "blocked.example.com")
			}
			return true
		},
	}

	reply, err := h.request(context.Background(), packDNSQuery("blocked.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(reply) == 0 {
		t.Fatal("expected non-empty reply")
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) != 0 {
		t.Errorf("len(Answer) = %d, want 0 (bypassed)", len(mr.Answer))
	}
}

func TestRequest_HostMapperHit(t *testing.T) {
	h := newInitdHandler()
	h.hostMapper = &mockHostMapper{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, bool) {
			return []net.IP{net.ParseIP("1.2.3.4")}, true
		},
	}

	reply, err := h.request(context.Background(), packDNSQuery("mapped.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1", len(mr.Answer))
	}
}

func TestRequest_NoExchanger(t *testing.T) {
	h := newInitdHandler()
	h.hop = nil
	h.exchangers = make(map[string]exchanger.Exchanger)

	_, err := h.request(context.Background(), packDNSQuery("none.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err == nil {
		t.Fatal("expected error when no exchanger")
	}
	if got := err.Error(); got != "exchange not found for none.example.com." {
		t.Errorf("error = %q, want to contain 'exchange not found'", got)
	}
}

func TestRequest_CacheHit(t *testing.T) {
	h := newInitdHandler()

	q := new(dns.Msg)
	q.SetQuestion("cached.example.com.", dns.TypeA)
	respMsg := q.Copy()
	respMsg.Answer = []dns.RR{mustNewRR("cached.example.com. 300 IN A 9.8.7.6")}
	key := resolver_util.NewCacheKey(&q.Question[0])
	h.cache.Store(context.Background(), key, respMsg, 30*time.Second)

	reply, err := h.request(context.Background(), packDNSQuery("cached.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1 (cached)", len(mr.Answer))
	}
}

func TestRequest_ExchangeSuccess(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("test.example.com.", dns.TypeA)
	respMsg := query.Copy()
	respMsg.Answer = []dns.RR{mustNewRR("test.example.com. 60 IN A 10.0.0.1")}
	respBytes, _ := respMsg.Pack()

	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			return respBytes, nil
		},
		addr: "udp://8.8.8.8:53",
	}

	h := newInitdHandler()
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx

	reply, err := h.request(context.Background(), packDNSQuery("test.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1", len(mr.Answer))
	}
}

// ---------------------------------------------------------------------------
// Tests: Handle (integration)
// ---------------------------------------------------------------------------

func TestHandle_BasicQuery(t *testing.T) {
	answerRR := mustNewRR("test.example.com. 60 IN A 10.0.0.1")
	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			mq := new(dns.Msg)
			_ = mq.Unpack(msg)
			resp := mq.Copy()
			resp.Answer = []dns.RR{answerRR}
			return resp.Pack()
		},
		addr: "udp://8.8.8.8:53",
	}

	h := newInitdHandler()
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx

	conn := newStringConn(packDNSQuery("test.example.com.", dns.TypeA))
	if err := h.Handle(context.Background(), conn); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	written := conn.writeBuf.Bytes()
	if len(written) == 0 {
		t.Fatal("expected response written to conn")
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(written); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1", len(mr.Answer))
	}
}

func TestHandle_RateLimited(t *testing.T) {
	h := newInitdHandler()
	h.options.RateLimiter = &mockRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &mockLimiter{allowFn: func(n int) bool { return false }}
		},
	}
	conn := newStringConn(packDNSQuery("test.example.com.", dns.TypeA))
	if err := h.Handle(context.Background(), conn); err == nil {
		t.Fatal("expected error when rate limited")
	}
}

func TestHandle_InvalidData(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn([]byte{0xFF, 0xFF, 0xFF})
	if err := h.Handle(context.Background(), conn); err == nil {
		t.Fatal("expected error for invalid DNS data")
	}
}

func TestHandle_ReadTimeout(t *testing.T) {
	h := newTestHandler()
	h.md.readTimeout = 50 * time.Millisecond
	h.md.timeout = defaultTimeout
	h.md.bufferSize = defaultBufferSize
	h.cache = resolver_util.NewCache().WithLogger(nopLog())

	conn := &slowConn{readDelay: 200 * time.Millisecond}
	if err := h.Handle(context.Background(), conn); err == nil {
		t.Fatal("expected error from slow read")
	}
}

// ---------------------------------------------------------------------------
// Tests: async mode
// ---------------------------------------------------------------------------

func TestRequest_AsyncRefresh(t *testing.T) {
	var (
		answerRR = mustNewRR("async.example.com. 300 IN A 10.0.0.1")
		done     = make(chan struct{})
	)

	h := newInitdHandler()
	h.md.async = true
	h.md.ttl = 30 * time.Second

	// Pre-populate cache with a tiny TTL so it expires before the request.
	// The async path triggers when: cache hit but TTL <= 0.
	q := new(dns.Msg)
	q.SetQuestion("async.example.com.", dns.TypeA)
	respMsg := q.Copy()
	respMsg.Answer = []dns.RR{answerRR}
	key := resolver_util.NewCacheKey(&q.Question[0])
	h.cache.Store(context.Background(), key, respMsg, time.Nanosecond)
	time.Sleep(5 * time.Millisecond) // let entry expire

	// Set up exchanger for async refresh
	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			defer close(done)

			mq := new(dns.Msg)
			_ = mq.Unpack(msg)
			resp := mq.Copy()
			resp.Answer = []dns.RR{answerRR}
			return resp.Pack()
		},
		addr: "udp://8.8.8.8:53",
	}

	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx

	reply, err := h.request(context.Background(), packDNSQuery("async.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1 (cached)", len(mr.Answer))
	}

	// Wait for async goroutine via channel synchronization.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("async exchange did not occur within timeout")
	}
}

// ---------------------------------------------------------------------------
// Tests: Concurrent access
// ---------------------------------------------------------------------------

func TestHandle_ConcurrentRequests(t *testing.T) {
	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			mq := new(dns.Msg)
			_ = mq.Unpack(msg)
			resp := mq.Copy()
			rr := mustNewRR(fmt.Sprintf("%s 60 IN A 10.0.0.1", mq.Question[0].Name))
			resp.Answer = []dns.RR{rr}
			return resp.Pack()
		},
		addr: "udp://8.8.8.8:53",
	}

	h := newInitdHandler()
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("test%d.example.com.", i)
			conn := newStringConn(packDNSQuery(name, dns.TypeA))
			if err := h.Handle(context.Background(), conn); err != nil {
				t.Errorf("Handle(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Tests: async error handling
// ---------------------------------------------------------------------------

func TestRequest_AsyncExchangeError(t *testing.T) {
	answerRR := mustNewRR("async-err.example.com. 300 IN A 10.0.0.1")

	h := newInitdHandler()
	h.md.async = true
	h.md.ttl = 30 * time.Second

	// Pre-populate cache with expired entry.
	q := new(dns.Msg)
	q.SetQuestion("async-err.example.com.", dns.TypeA)
	respMsg := q.Copy()
	respMsg.Answer = []dns.RR{answerRR}
	key := resolver_util.NewCacheKey(&q.Question[0])
	h.cache.Store(context.Background(), key, respMsg, time.Nanosecond)
	time.Sleep(5 * time.Millisecond)

	done := make(chan struct{})
	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			defer close(done)
			return nil, errors.New("upstream unreachable")
		},
		addr: "udp://8.8.8.8:53",
	}

	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx

	// The stale response should still be returned despite async error.
	reply, err := h.request(context.Background(), packDNSQuery("async-err.example.com.", dns.TypeA), newRecObj(), nopLog())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(reply); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Errorf("len(Answer) = %d, want 1 (stale cached)", len(mr.Answer))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("async exchange did not complete within timeout")
	}
}

// ---------------------------------------------------------------------------
// Tests: write deadline
// ---------------------------------------------------------------------------

func TestHandle_WriteDeadline(t *testing.T) {
	answerRR := mustNewRR("timeout.example.com. 60 IN A 10.0.0.1")
	mockEx := &mockExchanger{
		exchangeFn: func(ctx context.Context, msg []byte) ([]byte, error) {
			mq := new(dns.Msg)
			_ = mq.Unpack(msg)
			resp := mq.Copy()
			resp.Answer = []dns.RR{answerRR}
			return resp.Pack()
		},
		addr: "udp://8.8.8.8:53",
	}

	h := newTestHandler()
	h.md.readTimeout = 50 * time.Millisecond
	h.md.timeout = defaultTimeout
	h.md.bufferSize = defaultBufferSize
	h.cache = resolver_util.NewCache().WithLogger(nopLog())
	h.hop = &mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("ns1", "udp://8.8.8.8:53")
		},
	}
	h.exchangers["ns1"] = mockEx

	conn := &blockingWriteConn{
		readBuf: bytes.NewBuffer(packDNSQuery("timeout.example.com.", dns.TypeA)),
	}
	if err := h.Handle(context.Background(), conn); err == nil {
		t.Fatal("expected error from blocked write")
	}
}

// blockingWriteConn is a net.Conn where Write blocks forever.
type blockingWriteConn struct {
	readBuf *bytes.Buffer
}

func (c *blockingWriteConn) Read(b []byte) (int, error)  { return c.readBuf.Read(b) }
func (c *blockingWriteConn) Write(b []byte) (int, error) { time.Sleep(200 * time.Millisecond); return 0, errors.New("write deadline exceeded") }
func (c *blockingWriteConn) Close() error                             { return nil }
func (c *blockingWriteConn) LocalAddr() net.Addr                      { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53} }
func (c *blockingWriteConn) RemoteAddr() net.Addr                     { return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345} }
func (c *blockingWriteConn) SetDeadline(t time.Time) error            { return nil }
func (c *blockingWriteConn) SetReadDeadline(t time.Time) error        { return nil }
func (c *blockingWriteConn) SetWriteDeadline(t time.Time) error       { return nil }
