package selector

import (
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
)

// mockTransport implements chain.Transporter for testing.
type mockTransport struct {
	dialResult   net.Conn
	dialErr      error
	handshakeErr error
	connectErr   error
	bindErr      error
}

func (m *mockTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	return m.dialResult, nil
}

func (m *mockTransport) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if m.handshakeErr != nil {
		return nil, m.handshakeErr
	}
	return conn, nil
}

func (m *mockTransport) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	if m.connectErr != nil {
		return nil, m.connectErr
	}
	return conn, nil
}

func (m *mockTransport) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	if m.bindErr != nil {
		return nil, m.bindErr
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func (m *mockTransport) Multiplex() bool                  { return false }
func (m *mockTransport) Options() *chain.TransportOptions { return &chain.TransportOptions{} }
func (m *mockTransport) Copy() chain.Transporter          { return m }

func makeNode(tr chain.Transporter) *chain.Node {
	return chain.NewNode("test", "127.0.0.1:0", chain.TransportNodeOption(tr))
}

// --- ParallelStrategy ---

func TestParallelStrategy_Empty(t *testing.T) {
	s := ParallelStrategy[*chain.Node]()
	if v := s.Apply(context.Background()); v != nil {
		t.Fatalf("expected nil, got %v", v)
	}
}

func TestParallelStrategy_Single(t *testing.T) {
	s := ParallelStrategy[*chain.Node]()
	tr := &mockTransport{}
	node := makeNode(tr)

	result := s.Apply(context.Background(), node)
	if result == nil {
		t.Fatal("expected non-nil result for single node")
	}
}

func TestParallelStrategy_MultipleNodes(t *testing.T) {
	s := ParallelStrategy[*chain.Node]()
	nodes := []*chain.Node{
		makeNode(&mockTransport{}),
		makeNode(&mockTransport{}),
		makeNode(&mockTransport{}),
	}

	result := s.Apply(context.Background(), nodes[0], nodes[1], nodes[2])
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParallelStrategy_NonNodeInput(t *testing.T) {
	s := ParallelStrategy[string]()
	// Single non-node input: len==1 returns vs[0] directly
	if v := s.Apply(context.Background(), "hello"); v != "hello" {
		t.Fatalf("expected 'hello' for single input, got %q", v)
	}

	// Multiple non-node inputs: type assertion fails, returns zero value
	if v := s.Apply(context.Background(), "a", "b"); v != "" {
		t.Fatalf("expected zero value for multiple non-node inputs, got %q", v)
	}
}

// --- parallel limit tests ---

// parallelNodes returns the nodes held by the parallel transporter of the
// selected node.
func parallelNodes(t *testing.T, node *chain.Node) []*chain.Node {
	t.Helper()

	tr, ok := node.Options().Transport.(*parallelTransporter)
	if !ok {
		t.Fatalf("expected *parallelTransporter, got %T", node.Options().Transport)
	}
	return tr.nodes
}

// makeNodes builds n distinguishable nodes.
func makeNodes(n int) []*chain.Node {
	nodes := make([]*chain.Node, n)
	for i := range nodes {
		nodes[i] = makeNode(&mockTransport{})
	}
	return nodes
}

func TestParallelStrategy_NoLimit(t *testing.T) {
	s := ParallelStrategy[*chain.Node]()
	nodes := makeNodes(3)

	got := parallelNodes(t, s.Apply(context.Background(), nodes...))
	if len(got) != 3 {
		t.Fatalf("expected all 3 nodes to race, got %d", len(got))
	}
}

func TestParallelStrategy_LimitNotSmallerThanPool(t *testing.T) {
	nodes := makeNodes(3)

	for _, limit := range []int{3, 4, 100} {
		s := ParallelStrategy[*chain.Node](ParallelLimit(limit))
		got := parallelNodes(t, s.Apply(context.Background(), nodes...))
		if len(got) != 3 {
			t.Fatalf("limit %d: expected all 3 nodes to race, got %d", limit, len(got))
		}
	}
}

func TestParallelStrategy_NegativeLimit(t *testing.T) {
	s := ParallelStrategy[*chain.Node](ParallelLimit(-1))
	nodes := makeNodes(3)

	got := parallelNodes(t, s.Apply(context.Background(), nodes...))
	if len(got) != 3 {
		t.Fatalf("expected all 3 nodes to race, got %d", len(got))
	}
}

func TestParallelStrategy_LimitRoundRobin(t *testing.T) {
	s := ParallelStrategy[*chain.Node](ParallelLimit(2))
	nodes := makeNodes(8)

	// The offset advances by the limit on every call, so consecutive races
	// use disjoint groups.
	for i := 0; i < 4; i++ {
		got := parallelNodes(t, s.Apply(context.Background(), nodes...))
		if len(got) != 2 {
			t.Fatalf("race %d: expected 2 nodes, got %d", i, len(got))
		}
		want := nodes[i*2 : i*2+2]
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("race %d: node %d is %p, want %p", i, j, got[j], want[j])
			}
		}
	}
}

func TestParallelStrategy_LimitRoundRobinWrapsAround(t *testing.T) {
	s := ParallelStrategy[*chain.Node](ParallelLimit(3))
	nodes := makeNodes(8)

	// 8 nodes with a limit of 3 does not divide evenly, the selection must
	// still wrap around without repeating a node within a race.
	for i := 0; i < 6; i++ {
		got := parallelNodes(t, s.Apply(context.Background(), nodes...))
		if len(got) != 3 {
			t.Fatalf("race %d: expected 3 nodes, got %d", i, len(got))
		}
		seen := map[*chain.Node]bool{}
		for _, n := range got {
			if seen[n] {
				t.Fatalf("race %d: duplicate node selected", i)
			}
			seen[n] = true
		}
	}
}

func TestParallelStrategy_LimitRandom(t *testing.T) {
	s := ParallelStrategy[*chain.Node](ParallelLimit(3), ParallelMode("random"))
	nodes := makeNodes(10)

	seen := map[*chain.Node]bool{}
	for i := 0; i < 200; i++ {
		got := parallelNodes(t, s.Apply(context.Background(), nodes...))
		if len(got) != 3 {
			t.Fatalf("race %d: expected 3 nodes, got %d", i, len(got))
		}
		race := map[*chain.Node]bool{}
		for _, n := range got {
			if race[n] {
				t.Fatalf("race %d: duplicate node selected", i)
			}
			race[n] = true
			seen[n] = true
		}
	}

	// Over 200 races of 3 out of 10 nodes every node is expected to have
	// taken part at least once.
	for _, n := range nodes {
		if !seen[n] {
			t.Fatal("node never took part in a race")
		}
	}
}

func TestParallelStrategy_ModeUnknownFallsBackToRoundRobin(t *testing.T) {
	s := ParallelStrategy[*chain.Node](ParallelLimit(2), ParallelMode("bogus"))
	nodes := makeNodes(4)

	got := parallelNodes(t, s.Apply(context.Background(), nodes...))
	want := nodes[0:2]
	for j := range want {
		if got[j] != want[j] {
			t.Fatalf("node %d is %p, want %p", j, got[j], want[j])
		}
	}
}

func TestParallelStrategy_ModeAliases(t *testing.T) {
	nodes := makeNodes(4)

	for _, mode := range []string{"", "round", "rr", "roundrobin", "ROUND"} {
		s := ParallelStrategy[*chain.Node](ParallelLimit(2), ParallelMode(mode))
		got := parallelNodes(t, s.Apply(context.Background(), nodes...))
		want := nodes[0:2]
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("mode %q: node %d is %p, want %p", mode, j, got[j], want[j])
			}
		}
	}

	for _, mode := range []string{"random", "rand", "Random"} {
		s := ParallelStrategy[*chain.Node](ParallelLimit(2), ParallelMode(mode))
		got := parallelNodes(t, s.Apply(context.Background(), nodes...))
		if len(got) != 2 {
			t.Fatalf("mode %q: expected 2 nodes, got %d", mode, len(got))
		}
	}
}

// --- parallelTransporter unit tests ---

func TestParallelTransporter_Dial_NoNodes(t *testing.T) {
	tr := &parallelTransporter{nodes: nil}
	_, err := tr.Dial(context.Background(), "")
	if err == nil {
		t.Fatal("expected error with no nodes")
	}
}

func TestParallelTransporter_Copy(t *testing.T) {
	nodes := []*chain.Node{makeNode(&mockTransport{}), makeNode(&mockTransport{})}
	tr := &parallelTransporter{nodes: nodes}

	cp := tr.Copy()
	cpTr := cp.(*parallelTransporter)

	if len(cpTr.nodes) != len(tr.nodes) {
		t.Fatalf("copy should have same number of nodes: %d vs %d", len(cpTr.nodes), len(tr.nodes))
	}

	// Should be a shallow copy of the slice (different backing array)
	cpTr.nodes[0] = nil
	if tr.nodes[0] == nil {
		t.Fatal("copy should not share backing array")
	}
}

func TestParallelTransporter_Multiplex(t *testing.T) {
	tr := &parallelTransporter{}
	if tr.Multiplex() {
		t.Fatal("parallel transporter should not multiplex")
	}
}

func TestParallelTransporter_Options(t *testing.T) {
	tr := &parallelTransporter{}
	if opts := tr.Options(); opts == nil {
		t.Fatal("expected non-nil options")
	}
}

func TestParallelTransporter_Handshake_NonParallelConn(t *testing.T) {
	tr := &parallelTransporter{}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn, err := tr.Handshake(context.Background(), c1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-parallelConn should be returned as-is
	if conn != c1 {
		t.Fatal("expected original conn for non-parallelConn")
	}
}

func TestParallelTransporter_Connect_NonParallelConn(t *testing.T) {
	tr := &parallelTransporter{}
	c1, _ := net.Pipe()
	defer c1.Close()

	_, err := tr.Connect(context.Background(), c1, "tcp", "addr")
	if err == nil {
		t.Fatal("expected error for non-parallelConn")
	}
}

func TestParallelTransporter_Bind_NonParallelConn(t *testing.T) {
	tr := &parallelTransporter{}
	c1, _ := net.Pipe()
	defer c1.Close()

	_, err := tr.Bind(context.Background(), c1, "tcp", "addr")
	if err == nil {
		t.Fatal("expected error for non-parallelConn")
	}
}

// --- parallelConn tests ---

func TestParallelConn_Handshake_Delegates(t *testing.T) {
	tr := &parallelTransporter{
		nodes: []*chain.Node{makeNode(&mockTransport{})},
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	pc := &parallelConn{Conn: c1, node: makeNode(&mockTransport{})}
	conn, err := tr.Handshake(context.Background(), pc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn after handshake")
	}
	conn.Close()
}

func TestParallelConn_Connect_Delegates(t *testing.T) {
	tr := &parallelTransporter{
		nodes: []*chain.Node{makeNode(&mockTransport{})},
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	pc := &parallelConn{Conn: c1, node: makeNode(&mockTransport{})}
	conn, err := tr.Connect(context.Background(), pc, "tcp", "127.0.0.1:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn after connect")
	}
	conn.Close()
}

func TestParallelConn_Bind_Delegates(t *testing.T) {
	tr := &parallelTransporter{
		nodes: []*chain.Node{makeNode(&mockTransport{})},
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	pc := &parallelConn{Conn: c1, node: makeNode(&mockTransport{})}
	ln, err := tr.Bind(context.Background(), pc, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ln.Close()
}
