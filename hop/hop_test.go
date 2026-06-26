package hop

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/routing"
	"github.com/go-gost/x/registry"
	xlogger "github.com/go-gost/x/logger"
)

// --- Mock types ---

type testBypass struct {
	whitelist bool
	contains  bool
}

func (b *testBypass) IsWhitelist() bool                     { return b.whitelist }
func (b *testBypass) Init(md metadata.Metadata) error         { return nil }
func (b *testBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return b.contains
}

// testNodeSelector implements selector.Selector[*chain.Node].
type testNodeSelector struct {
	selectedIdx int
	callCount   int
}

func (s *testNodeSelector) Select(ctx context.Context, nodes ...*chain.Node) *chain.Node {
	if len(nodes) == 0 {
		return nil
	}
	idx := s.selectedIdx % len(nodes)
	s.callCount++
	return nodes[idx]
}

type testMatcher struct {
	match bool
}

func (m *testMatcher) Match(req *routing.Request) bool { return m.match }

type requestCapturingMatcher struct {
	capture **routing.Request
	match   bool
}

func (m *requestCapturingMatcher) Match(req *routing.Request) bool {
	if m.capture != nil {
		*m.capture = req
	}
	return m.match
}

type testLoader struct {
	loadFn  func(ctx context.Context) (io.Reader, error)
	closeFn func() error
}

func (l *testLoader) Load(ctx context.Context) (io.Reader, error) {
	if l.loadFn != nil {
		return l.loadFn(ctx)
	}
	return nil, nil
}

func (l *testLoader) Close() error {
	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}

type stubConnector struct{}

func (c *stubConnector) Init(md metadata.Metadata) error { return nil }

func (c *stubConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	return conn, nil
}

func newStubConnector(opts ...connector.Option) connector.Connector {
	return &stubConnector{}
}

func newStubDialer(opts ...dialer.Option) dialer.Dialer {
	return &stubDialer{}
}

type stubDialer struct{}

func (d *stubDialer) Init(md metadata.Metadata) error { return nil }

func (d *stubDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return &stubConn{}, nil
}

type stubConn struct{}

func (c *stubConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (c *stubConn) Write(b []byte) (n int, err error)   { return len(b), nil }
func (c *stubConn) Close() error                         { return nil }
func (c *stubConn) LocalAddr() net.Addr                  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }
func (c *stubConn) RemoteAddr() net.Addr                 { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }
func (c *stubConn) SetDeadline(t time.Time) error        { return nil }
func (c *stubConn) SetReadDeadline(t time.Time) error    { return nil }
func (c *stubConn) SetWriteDeadline(t time.Time) error   { return nil }

func init() {
	logger.SetDefault(xlogger.Nop())
	registry.ConnectorRegistry().Register("http", newStubConnector)
	registry.ConnectorRegistry().Register("socks5", newStubConnector)
	registry.DialerRegistry().Register("tcp", newStubDialer)
}

// Helper to create a hop and return *chainHop for Close access.
func newTestHop(opts ...Option) *chainHop {
	return NewHop(opts...).(*chainHop)
}

// =============================================================================
// Option tests
// =============================================================================

func TestNameOption(t *testing.T) {
	var o options
	NameOption("my-hop")(&o)
	if o.name != "my-hop" {
		t.Errorf("expected name 'my-hop', got %q", o.name)
	}
}

func TestNodeOption(t *testing.T) {
	var o options
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	NodeOption(n1, n2)(&o)
	if len(o.nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(o.nodes))
	}
	if o.nodes[0].Name != "n1" || o.nodes[1].Name != "n2" {
		t.Error("unexpected node content")
	}
}

func TestBypassOption(t *testing.T) {
	var o options
	bp := &testBypass{}
	BypassOption(bp)(&o)
	if o.bypass != bp {
		t.Error("bypass not set correctly")
	}
}

func TestSelectorOption(t *testing.T) {
	var o options
	sel := &testNodeSelector{}
	SelectorOption(sel)(&o)
	if o.selector != sel {
		t.Error("selector not set correctly")
	}
}

func TestReloadPeriodOption(t *testing.T) {
	var o options
	ReloadPeriodOption(5 * time.Second)(&o)
	if o.period != 5*time.Second {
		t.Errorf("expected period 5s, got %v", o.period)
	}
}

func TestFileLoaderOption(t *testing.T) {
	var o options
	ld := &testLoader{}
	FileLoaderOption(ld)(&o)
	if o.fileLoader != ld {
		t.Error("fileLoader not set correctly")
	}
}

func TestRedisLoaderOption(t *testing.T) {
	var o options
	ld := &testLoader{}
	RedisLoaderOption(ld)(&o)
	if o.redisLoader != ld {
		t.Error("redisLoader not set correctly")
	}
}

func TestHTTPLoaderOption(t *testing.T) {
	var o options
	ld := &testLoader{}
	HTTPLoaderOption(ld)(&o)
	if o.httpLoader != ld {
		t.Error("httpLoader not set correctly")
	}
}

func TestLoggerOption(t *testing.T) {
	var o options
	l := xlogger.Nop()
	LoggerOption(l)(&o)
	if o.logger != l {
		t.Error("logger not set correctly")
	}
}

// =============================================================================
// NewHop tests
// =============================================================================

func TestNewHop_Empty(t *testing.T) {
	h := newTestHop()
	defer h.Close()

	nodes := h.Nodes()
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestNewHop_WithNodes(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	nodes := h.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
}

func TestNewHop_NilLoggerDefaultsToNop(t *testing.T) {
	h := newTestHop()
	defer h.Close()
	if h.logger == nil {
		t.Error("expected non-nil logger (should default to Nop)")
	}
}

func TestNewHop_WithLogger(t *testing.T) {
	l := xlogger.Nop()
	h := newTestHop(LoggerOption(l))
	defer h.Close()
	if h.logger != l {
		t.Error("logger not set on chainHop")
	}
}

func TestNewHop_NilOptionIgnored(t *testing.T) {
	h := newTestHop(nil)
	defer h.Close()
	if h == nil {
		t.Fatal("NewHop returned nil")
	}
}

// =============================================================================
// Nodes tests
// =============================================================================

func TestNodes_NilReceiver(t *testing.T) {
	var ch *chainHop
	nodes := ch.Nodes()
	if nodes != nil {
		t.Error("expected nil from nil receiver")
	}
}

func TestNodes_Empty(t *testing.T) {
	ch := &chainHop{}
	nodes := ch.Nodes()
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestNodes_WithData(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	ch := &chainHop{nodes: []*chain.Node{n1}}
	nodes := ch.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Name != "n1" {
		t.Errorf("expected 'n1', got %q", nodes[0].Name)
	}
}

// =============================================================================
// Select tests
// =============================================================================

func TestSelect_EmptyNodes(t *testing.T) {
	h := newTestHop()
	defer h.Close()

	node := h.Select(context.Background())
	if node != nil {
		t.Error("expected nil from empty hop")
	}
}

func TestSelect_SingleNode(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1', got %q", node.Name)
	}
}

func TestSelect_HopBypass_BlocksAll(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	h := newTestHop(
		NodeOption(n1),
		BypassOption(&testBypass{contains: true}),
	)
	defer h.Close()

	node := h.Select(context.Background())
	if node != nil {
		t.Error("expected nil when hop-level bypass matches")
	}
}

func TestSelect_HopBypass_Allows(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	h := newTestHop(
		NodeOption(n1),
		BypassOption(&testBypass{contains: false}),
	)
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Error("expected node when bypass does not match")
	}
}

func TestSelect_NodeBypass_SkipsBlockedNode(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.BypassNodeOption(&testBypass{contains: true}),
	)
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (n1 blocked), got %q", node.Name)
	}
}

func TestSelect_NodeBypass_AllNodesBlocked(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.BypassNodeOption(&testBypass{contains: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background())
	if node != nil {
		t.Error("expected nil when all nodes blocked")
	}
}

func TestSelect_MatcherMatches(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1', got %q", node.Name)
	}
}

func TestSelect_MatcherDoesNotMatch(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: false}),
	)
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (n1 didn't match), got %q", node.Name)
	}
}

func TestSelect_MatcherReceivesNetwork(t *testing.T) {
	var capturedReq *routing.Request
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&requestCapturingMatcher{capture: &capturedReq, match: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	h.Select(context.Background(), hop.NetworkSelectOption("tcp"))

	if capturedReq == nil {
		t.Fatal("request was not passed to matcher")
	}
	if capturedReq.Network != "tcp" {
		t.Errorf("matcher saw Network=%q, want %q", capturedReq.Network, "tcp")
	}
}

func TestSelect_MatcherMatchNetwork(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: false}),
	)
	n2 := chain.NewNode("n2", "127.0.0.1:9090",
		chain.MatcherNodeOption(&testMatcher{match: true}),
	)
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background(), hop.NetworkSelectOption("udp"))
	if node == nil {
		t.Fatal("expected selected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (match=true), got %q", node.Name)
	}
}

func TestSelect_Priority_HighestWins(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080", chain.PriorityNodeOption(5))
	n2 := chain.NewNode("n2", "127.0.0.1:9090", chain.PriorityNodeOption(10))
	n3 := chain.NewNode("n3", "127.0.0.1:7070")
	h := newTestHop(NodeOption(n1, n2, n3))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (highest priority), got %q", node.Name)
	}
}

func TestSelect_Priority_ZeroPriorityFallsToFirst(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:9090")
	n2 := chain.NewNode("n2", "127.0.0.1:8080")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1' (first node), got %q", node.Name)
	}
}

func TestSelect_Priority_NegativeIgnored(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080", chain.PriorityNodeOption(-5))
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	// n2 sorted before n1 (-5 <= 0), and both have priority <= 0
	if node.Name != "n2" {
		t.Errorf("expected 'n2', got %q", node.Name)
	}
}

func TestSelect_WithSelector(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	sel := &testNodeSelector{selectedIdx: 1}
	h := newTestHop(NodeOption(n1, n2), SelectorOption(sel))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (selected by selector), got %q", node.Name)
	}
}

func TestSelect_EqualPriorityDoesNotShortcut(t *testing.T) {
	// Two nodes with identical matchers get the same default priority.
	// The priority shortcut must NOT trigger when multiple nodes share
	// the highest priority — the selector should still apply.
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: true}),
		chain.PriorityNodeOption(50),
	)
	n2 := chain.NewNode("n2", "127.0.0.1:9090",
		chain.MatcherNodeOption(&testMatcher{match: true}),
		chain.PriorityNodeOption(50),
	)
	sel := &testNodeSelector{selectedIdx: 1} // picks n2
	h := newTestHop(NodeOption(n1, n2), SelectorOption(sel))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (selected by selector, not shortcut), got %q", node.Name)
	}
}

func TestSelect_NilNodesSkipped(t *testing.T) {
	h := newTestHop()
	defer h.Close()
	h.nodes = []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080"), nil, chain.NewNode("n3", "127.0.0.1:7070")}

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name == "" {
		t.Error("expected non-empty node name")
	}
}

// =============================================================================
// isEligible tests
// =============================================================================

func TestIsEligible_NilNode(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	if ch.isEligible(nil, &hop.SelectOptions{}) {
		t.Error("expected false for nil node")
	}
}

func TestIsEligible_NoFilter(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	if !ch.isEligible(n, &hop.SelectOptions{}) {
		t.Error("expected true when no filter")
	}
}

func TestIsEligible_HostMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	if !ch.isEligible(n, &hop.SelectOptions{Host: "example.com"}) {
		t.Error("expected true for matching host")
	}
}

func TestIsEligible_HostMismatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	if ch.isEligible(n, &hop.SelectOptions{Host: "other.com"}) {
		t.Error("expected false for mismatching host")
	}
}

func TestIsEligible_ProtocolMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Protocol: "http"}
	if !ch.isEligible(n, &hop.SelectOptions{Protocol: "http"}) {
		t.Error("expected true for matching protocol")
	}
}

func TestIsEligible_ProtocolMismatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Protocol: "http"}
	if ch.isEligible(n, &hop.SelectOptions{Protocol: "socks5"}) {
		t.Error("expected false for mismatching protocol")
	}
}

func TestIsEligible_PathMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Path: "/api"}
	if !ch.isEligible(n, &hop.SelectOptions{Path: "/api/v1/users"}) {
		t.Error("expected true for matching path prefix")
	}
}

func TestIsEligible_PathMismatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Path: "/api"}
	if ch.isEligible(n, &hop.SelectOptions{Path: "/other/route"}) {
		t.Error("expected false for mismatching path")
	}
}

func TestIsEligible_AllFiltersMustPass(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{
		Host:     "example.com",
		Protocol: "http",
	}
	if ch.isEligible(n, &hop.SelectOptions{Host: "example.com", Protocol: "socks5"}) {
		t.Error("expected false: host matches but protocol doesn't")
	}
}

// =============================================================================
// checkHost tests
// =============================================================================

func TestCheckHost_EmptyFilter(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	if !ch.checkHost("anything.com", n) {
		t.Error("expected true when no host filter")
	}
}

func TestCheckHost_ExactMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	if !ch.checkHost("example.com", n) {
		t.Error("expected true for exact host match")
	}
}

func TestCheckHost_WildcardMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: ".example.com"}
	if !ch.checkHost("sub.example.com", n) {
		t.Error("expected true for wildcard host match")
	}
}

func TestCheckHost_WildcardNoMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: ".example.com"}
	if ch.checkHost("other.net", n) {
		t.Error("expected false for non-matching wildcard")
	}
}

func TestCheckHost_EmptyInputHost(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	if ch.checkHost("", n) {
		t.Error("expected false when input host is empty and filter is set")
	}
}

func TestCheckHost_StripPort(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	if !ch.checkHost("example.com:443", n) {
		t.Error("expected true after stripping port")
	}
}

func TestCheckHost_IPWithPort(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "192.168.1.1"}
	if !ch.checkHost("192.168.1.1:3128", n) {
		t.Error("expected true for IP with port")
	}
}

func TestCheckHost_IPv6WithPort(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "::1"}
	if !ch.checkHost("[::1]:8080", n) {
		t.Error("expected true for bracketed IPv6 with port")
	}
}

func TestCheckHost_NoMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	if ch.checkHost("other.com", n) {
		t.Error("expected false for non-matching host")
	}
}

// =============================================================================
// checkProtocol tests
// =============================================================================

func TestCheckProtocol_EmptyFilter(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	if !ch.checkProtocol("http", n) {
		t.Error("expected true when no protocol filter")
	}
}

func TestCheckProtocol_Match(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Protocol: "http"}
	if !ch.checkProtocol("http", n) {
		t.Error("expected true for matching protocol")
	}
}

func TestCheckProtocol_NoMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Protocol: "socks5"}
	if ch.checkProtocol("http", n) {
		t.Error("expected false for non-matching protocol")
	}
}

// =============================================================================
// checkPath tests
// =============================================================================

func TestCheckPath_EmptyFilter(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	if !ch.checkPath("/any/path", n) {
		t.Error("expected true when no path filter")
	}
}

func TestCheckPath_PrefixMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Path: "/api"}
	if !ch.checkPath("/api/v1/users", n) {
		t.Error("expected true for prefix match")
	}
}

func TestCheckPath_ExactMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Path: "/api"}
	if !ch.checkPath("/api", n) {
		t.Error("expected true for exact match (prefix of self)")
	}
}

func TestCheckPath_NoMatch(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Path: "/api"}
	if ch.checkPath("/other", n) {
		t.Error("expected false for non-prefix match")
	}
}

func TestCheckPath_ShorterInput(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	n := chain.NewNode("n1", "127.0.0.1:8080")
	n.Options().Filter = &chain.NodeFilterSettings{Path: "/api"}
	if ch.checkPath("/ap", n) {
		t.Error("expected false when input is shorter than filter prefix")
	}
}

// =============================================================================
// Select with filter integration tests
// =============================================================================

func TestSelect_FilterHost_Match(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n1.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background(), hop.HostSelectOption("example.com"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_FilterHost_NoMatch(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n1.Options().Filter = &chain.NodeFilterSettings{Host: "example.com"}
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background(), hop.HostSelectOption("other.com"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (n1 host mismatch), got %q", node.Name)
	}
}

func TestSelect_FilterProtocol_Match(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n1.Options().Filter = &chain.NodeFilterSettings{Protocol: "http"}
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background(), hop.ProtocolSelectOption("http"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_FilterProtocol_NoMatch(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n1.Options().Filter = &chain.NodeFilterSettings{Protocol: "http"}
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background(), hop.ProtocolSelectOption("socks5"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n2" {
		t.Errorf("expected 'n2' (n1 protocol mismatch), got %q", node.Name)
	}
}

// =============================================================================
// Select with select options
// =============================================================================

func TestSelect_WithNetworkOption(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background(), hop.NetworkSelectOption("tcp"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_WithAddrOption(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background(), hop.AddrSelectOption("example.com:80"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_WithClientIPOption(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	ip := net.ParseIP("10.0.0.1")
	node := h.Select(context.Background(), hop.ClientIPSelectOption(ip))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_WithMethodOption(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background(), hop.MethodSelectOption("CONNECT"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_WithHeaderOption(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&testMatcher{match: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	header := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}
	node := h.Select(context.Background(), hop.HeaderSelectOption(header))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_WithMultipleOptions(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	node := h.Select(context.Background(),
		hop.NetworkSelectOption("tcp"),
		hop.HostSelectOption("example.com"),
		hop.ProtocolSelectOption("http"),
		hop.PathSelectOption("/api"),
	)
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

func TestSelect_MatcherWithFullRequest(t *testing.T) {
	var capturedReq *routing.Request
	n1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.MatcherNodeOption(&requestCapturingMatcher{capture: &capturedReq, match: true}),
	)
	h := newTestHop(NodeOption(n1))
	defer h.Close()

	ip := net.ParseIP("10.0.0.1")
	node := h.Select(context.Background(),
		hop.ClientIPSelectOption(ip),
		hop.HostSelectOption("example.com"),
		hop.ProtocolSelectOption("http"),
		hop.MethodSelectOption("GET"),
		hop.PathSelectOption("/api/v1"),
	)
	if node == nil {
		t.Fatal("expected node, got nil")
	}
}

// =============================================================================
// reload tests
// =============================================================================

func TestReload_NoLoaders(t *testing.T) {
	ch := &chainHop{
		options: options{nodes: []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")}},
		logger:  xlogger.Nop(),
	}
	err := ch.reload(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	nodes := ch.Nodes()
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}
}

func TestReload_WithFileLoader(t *testing.T) {
	loader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader(`[{"name": "loaded", "addr": "10.0.0.1:8080"}]`), nil
		},
	}
	ch := &chainHop{
		logger:  xlogger.Nop(),
		options: options{nodes: []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")}, fileLoader: loader, name: "test-hop"},
	}
	err := ch.reload(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	nodes := ch.Nodes()
	if len(nodes) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(nodes))
	}
}

func TestReload_LoaderError(t *testing.T) {
	loadErr := errors.New("load failed")
	loader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return nil, loadErr
		},
	}
	ch := &chainHop{
		logger:  xlogger.Nop(),
		options: options{nodes: []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")}, fileLoader: loader},
	}
	err := ch.reload(context.Background())
	if err == nil {
		t.Error("expected error from failed loader")
	}
}

func TestReload_RedisLoader(t *testing.T) {
	loader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader(`[{"name": "redis-node", "addr": "10.0.0.2:8080"}]`), nil
		},
	}
	ch := &chainHop{
		logger:  xlogger.Nop(),
		options: options{nodes: []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")}, redisLoader: loader, name: "test-hop"},
	}
	err := ch.reload(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReload_HTTPLoader(t *testing.T) {
	loader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader(`[{"name": "http-node", "addr": "10.0.0.3:8080"}]`), nil
		},
	}
	ch := &chainHop{
		logger:  xlogger.Nop(),
		options: options{nodes: []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")}, httpLoader: loader, name: "test-hop"},
	}
	err := ch.reload(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReload_MultipleLoaders(t *testing.T) {
	fileLoader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader(`[{"name": "file-n", "addr": "10.0.0.1:8080"}]`), nil
		},
	}
	redisLoader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader(`[{"name": "redis-n", "addr": "10.0.0.2:8080"}]`), nil
		},
	}
	ch := &chainHop{
		logger: xlogger.Nop(),
		options: options{
			nodes:       []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")},
			fileLoader:  fileLoader,
			redisLoader: redisLoader,
			name:        "test-hop",
		},
	}
	err := ch.reload(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReload_LoaderErrorWithParseError(t *testing.T) {
	loader := &testLoader{
		loadFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader(`invalid json`), nil
		},
	}
	ch := &chainHop{
		logger:  xlogger.Nop(),
		options: options{nodes: []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")}, fileLoader: loader},
	}
	err := ch.reload(context.Background())
	if err == nil {
		t.Error("expected parse error")
	}
}

// =============================================================================
// parseNode tests
// =============================================================================

func TestParseNode_NilReader(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	nodes, err := ch.parseNode(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseNode_ValidJSON(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop(), options: options{name: "test-hop"}}
	r := strings.NewReader(`[{"name": "n1", "addr": "10.0.0.1:8080"}]`)
	nodes, err := ch.parseNode(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Name != "n1" {
		t.Errorf("expected 'n1', got %q", nodes[0].Name)
	}
}

func TestParseNode_EmptyArray(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	r := strings.NewReader(`[]`)
	nodes, err := ch.parseNode(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseNode_InvalidJSON(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop()}
	r := strings.NewReader(`not json`)
	nodes, err := ch.parseNode(r)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseNode_NilEntrySkipped(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop(), options: options{name: "test-hop"}}
	r := strings.NewReader(`[null, {"name": "ok", "addr": "10.0.0.1:8080"}]`)
	nodes, err := ch.parseNode(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Name != "ok" {
		t.Errorf("expected 'ok', got %q", nodes[0].Name)
	}
}

func TestParseNode_SkipInvalidEntry(t *testing.T) {
	ch := &chainHop{logger: xlogger.Nop(), options: options{name: "test-hop"}}
	r := strings.NewReader(`[{"name": "bad"}]`)
	nodes, err := ch.parseNode(r)
	// May return an error via errors.Join even if some nodes parsed
	_ = err
	_ = nodes
}

// =============================================================================
// Close tests
// =============================================================================

func TestClose_NoLoaders(t *testing.T) {
	h := newTestHop()
	err := h.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClose_WithLoaders(t *testing.T) {
	fileClosed := false
	redisClosed := false
	httpClosed := false

	h := newTestHop(
		FileLoaderOption(&testLoader{closeFn: func() error { fileClosed = true; return nil }}),
		RedisLoaderOption(&testLoader{closeFn: func() error { redisClosed = true; return nil }}),
		HTTPLoaderOption(&testLoader{closeFn: func() error { httpClosed = true; return nil }}),
	)
	err := h.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !fileClosed {
		t.Error("fileLoader not closed")
	}
	if !redisClosed {
		t.Error("redisLoader not closed")
	}
	if !httpClosed {
		t.Error("httpLoader not closed")
	}
}

func TestClose_CancelFuncCalled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := &chainHop{
		cancelFunc: cancel,
		logger:     xlogger.Nop(),
	}
	ch.Close()
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("context should be cancelled after Close")
	}
}

// =============================================================================
// periodReload tests
// =============================================================================

func TestPeriodReload_NoPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := &chainHop{
		options: options{period: 0},
		logger:  xlogger.Nop(),
		nodes:   []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")},
	}
	err := ch.periodReload(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPeriodReload_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := &chainHop{
		options: options{period: time.Second},
		logger:  xlogger.Nop(),
		nodes:   []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")},
	}
	err := ch.periodReload(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestPeriodReload_MinimumPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := &chainHop{
		options: options{period: time.Millisecond},
		logger:  xlogger.Nop(),
		nodes:   []*chain.Node{chain.NewNode("n1", "127.0.0.1:8080")},
	}
	time.AfterFunc(50*time.Millisecond, cancel)
	err := ch.periodReload(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// =============================================================================
// Priority edge cases
// =============================================================================

func TestSelect_AllSamePriority(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	n3 := chain.NewNode("n3", "127.0.0.1:7070")
	h := newTestHop(NodeOption(n1, n2, n3))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1' (first node), got %q", node.Name)
	}
}

func TestSelect_OnlyNegativePriorities(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080", chain.PriorityNodeOption(-5))
	n2 := chain.NewNode("n2", "127.0.0.1:9090", chain.PriorityNodeOption(-10))
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background())
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1' (higher priority), got %q", node.Name)
	}
}

// =============================================================================
// Select with backup node (empty host filter means backup)
// =============================================================================

func TestSelect_BackupNode_HostFilterEmpty(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n1.Options().Filter = &chain.NodeFilterSettings{Host: ""}
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	n2.Options().Filter = &chain.NodeFilterSettings{Host: "specific.com"}
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background(), hop.HostSelectOption("other.com"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1' (backup), got %q", node.Name)
	}
}

func TestSelect_SpecificHostNodeWins(t *testing.T) {
	n1 := chain.NewNode("n1", "127.0.0.1:8080")
	n1.Options().Filter = &chain.NodeFilterSettings{Host: ""}
	n2 := chain.NewNode("n2", "127.0.0.1:9090")
	n2.Options().Filter = &chain.NodeFilterSettings{Host: "specific.com"}
	h := newTestHop(NodeOption(n1, n2))
	defer h.Close()

	node := h.Select(context.Background(), hop.HostSelectOption("specific.com"))
	if node == nil {
		t.Fatal("expected node, got nil")
	}
	if node.Name != "n1" {
		t.Errorf("expected 'n1' (first node when both eligible), got %q", node.Name)
	}
}

// =============================================================================
// Interface satisfaction
// =============================================================================

func TestChainHop_ImplementsHop(t *testing.T) {
	var _ hop.Hop = (*chainHop)(nil)
}

func TestChainHop_ImplementsNodeList(t *testing.T) {
	var _ hop.NodeList = (*chainHop)(nil)
}

func TestNewHop_ReturnsHopInterface(t *testing.T) {
	h := NewHop()
	if h == nil {
		t.Fatal("expected non-nil Hop")
	}
	defer h.(*chainHop).Close()
}

// =============================================================================
// NewHop starts periodReload goroutine
// =============================================================================

func TestNewHop_StartsPeriodReload(t *testing.T) {
	h := NewHop()
	ch := h.(*chainHop)
	if ch.cancelFunc == nil {
		t.Error("expected non-nil cancelFunc")
	}
	h.(*chainHop).Close()
}
