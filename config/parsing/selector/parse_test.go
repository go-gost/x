package selector

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/x/config"
)

func TestParseChainSelector_Nil(t *testing.T) {
	sel := ParseChainSelector(nil)
	if sel != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseChainSelector_RoundRobin(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "round"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_RR(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "rr"})
	if sel == nil {
		t.Fatal("expected non-nil selector for rr strategy")
	}
}

func TestParseChainSelector_Random(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "random"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_Rand(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "rand"})
	if sel == nil {
		t.Fatal("expected non-nil selector for rand strategy")
	}
}

func TestParseChainSelector_FIFO(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "fifo"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_HA(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "ha"})
	if sel == nil {
		t.Fatal("expected non-nil selector for ha strategy")
	}
}

func TestParseChainSelector_Hash(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "hash"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseChainSelector_DefaultStrategy(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{Strategy: "unknown"})
	if sel == nil {
		t.Fatal("expected non-nil selector for unknown strategy (should default to round-robin)")
	}
}

func TestParseChainSelector_WithMaxFails(t *testing.T) {
	sel := ParseChainSelector(&config.SelectorConfig{
		Strategy:    "round",
		MaxFails:    3,
		FailTimeout: 0,
	})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Nil(t *testing.T) {
	sel := ParseNodeSelector(nil)
	if sel != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseNodeSelector_RoundRobin(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "round"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Random(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "random"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_FIFO(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "fifo"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Hash(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "hash"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestParseNodeSelector_Parallel(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "parallel"})
	if sel == nil {
		t.Fatal("expected non-nil selector for parallel strategy")
	}
}

func TestParseNodeSelector_DefaultStrategy(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "unknown"})
	if sel == nil {
		t.Fatal("expected non-nil selector for unknown strategy (should default to round-robin)")
	}
}

func TestDefaultNodeSelector(t *testing.T) {
	sel := DefaultNodeSelector()
	if sel == nil {
		t.Fatal("expected non-nil default node selector")
	}
}

func TestDefaultChainSelector(t *testing.T) {
	sel := DefaultChainSelector()
	if sel == nil {
		t.Fatal("expected non-nil default chain selector")
	}
}

// --- parallel strategy wiring ---

// stubTransport is a no-op chain.Transporter used to build test nodes.
type stubTransport struct{}

func (s *stubTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, nil
}

func (s *stubTransport) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (s *stubTransport) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	return conn, nil
}

func (s *stubTransport) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	return nil, nil
}

func (s *stubTransport) Multiplex() bool                  { return false }
func (s *stubTransport) Options() *chain.TransportOptions { return &chain.TransportOptions{} }
func (s *stubTransport) Copy() chain.Transporter          { return s }

// raceSize returns the number of nodes the parallel transporter of the
// selected node holds. The transporter type is unexported in the x/selector
// package, so the node list is read via reflection.
func raceSize(t *testing.T, node *chain.Node) int {
	t.Helper()

	tr := node.Options().Transport
	v := reflect.ValueOf(tr)
	if v.Kind() != reflect.Pointer {
		t.Fatalf("expected a pointer transport, got %T", tr)
	}
	f := v.Elem().FieldByName("nodes")
	if !f.IsValid() {
		t.Fatalf("transport %T has no nodes field", tr)
	}
	return f.Len()
}

func TestParseNodeSelector_ParallelMaxParallel(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{
		Strategy:    "parallel",
		MaxParallel: 2,
	})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}

	nodes := make([]*chain.Node, 5)
	for i := range nodes {
		nodes[i] = chain.NewNode("test", "127.0.0.1:0", chain.TransportNodeOption(&stubTransport{}))
	}

	node := sel.Select(context.Background(), nodes...)
	if node == nil {
		t.Fatal("expected a selected node")
	}
	if n := raceSize(t, node); n != 2 {
		t.Fatalf("expected 2 nodes to race, got %d", n)
	}
}

func TestParseNodeSelector_ParallelNoLimit(t *testing.T) {
	sel := ParseNodeSelector(&config.SelectorConfig{Strategy: "parallel"})
	if sel == nil {
		t.Fatal("expected non-nil selector")
	}

	nodes := make([]*chain.Node, 5)
	for i := range nodes {
		nodes[i] = chain.NewNode("test", "127.0.0.1:0", chain.TransportNodeOption(&stubTransport{}))
	}

	node := sel.Select(context.Background(), nodes...)
	if node == nil {
		t.Fatal("expected a selected node")
	}
	if n := raceSize(t, node); n != 5 {
		t.Fatalf("expected all 5 nodes to race, got %d", n)
	}
}
