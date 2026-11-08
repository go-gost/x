package selector

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/selector"
	xctx "github.com/go-gost/x/ctx"
	xmd "github.com/go-gost/x/metadata"
)

type stickyTestNode struct {
	name string
	md   metadata.Metadata
}

func newStickyTestNode(name string, weight int) *stickyTestNode {
	return &stickyTestNode{
		name: name,
		md:   xmd.NewMetadata(map[string]any{"weight": weight}),
	}
}

func (n *stickyTestNode) Metadata() metadata.Metadata { return n.md }

func stickyContext(session string) context.Context {
	return xctx.ContextWithClientID(context.Background(), xctx.ClientID(session))
}

func stickyNodeKey(n *stickyTestNode) string { return n.name }

func TestStickyHashStrategySameClientSameNode(t *testing.T) {
	nodes := []*stickyTestNode{
		newStickyTestNode("a", 1),
		newStickyTestNode("b", 1),
		newStickyTestNode("c", 1),
	}
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)
	ctx := stickyContext("session-1")

	first := s.Apply(ctx, nodes...)
	if first == nil {
		t.Fatal("first selection is nil")
	}
	for i := 0; i < 100; i++ {
		if got := s.Apply(ctx, nodes...); got != first {
			t.Fatalf("selection %d = %q, want %q", i, got.name, first.name)
		}
	}
}

func TestStickyHashStrategyWeightedDistribution(t *testing.T) {
	// Use the real x node-name shape. Similar keys expose weak hashes that
	// correlate the two rendezvous scores and skew the weights.
	nodes := []*stickyTestNode{
		newStickyTestNode("r/oc/oc", 10),
		newStickyTestNode("r/cc/cc", 3),
	}
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)

	const total = 10000
	heavy := 0
	for i := 0; i < total; i++ {
		got := s.Apply(stickyContext(fmt.Sprintf("sess-dist-%d", i)), nodes...)
		if got.name == "r/oc/oc" {
			heavy++
		}
	}
	share := float64(heavy) / total
	if share < 0.74 || share > 0.80 {
		t.Fatalf("heavy share = %.4f, want 10/13 (0.74-0.80)", share)
	}
}

func TestStickyHashStrategyNodeRemovalOnlyMovesItsSessions(t *testing.T) {
	a := newStickyTestNode("a", 1)
	b := newStickyTestNode("b", 1)
	c := newStickyTestNode("c", 1)
	nodes := []*stickyTestNode{a, b, c}
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)

	const total = 1000
	before := make([]string, total)
	for i := 0; i < total; i++ {
		before[i] = s.Apply(stickyContext(fmt.Sprintf("session-%d", i)), nodes...).name
	}

	remaining := []*stickyTestNode{a, c}
	for i := 0; i < total; i++ {
		got := s.Apply(stickyContext(fmt.Sprintf("session-%d", i)), remaining...)
		switch before[i] {
		case "a":
			if got.name != "a" {
				t.Fatalf("session %d moved from a to %q", i, got.name)
			}
		case "c":
			if got.name != "c" {
				t.Fatalf("session %d moved from c to %q", i, got.name)
			}
		case "b":
			if got.name != "a" && got.name != "c" {
				t.Fatalf("session %d on removed b selected %q", i, got.name)
			}
		}
	}
}

func TestStickyHashStrategyOrderIndependent(t *testing.T) {
	a := newStickyTestNode("a", 1)
	b := newStickyTestNode("b", 1)
	c := newStickyTestNode("c", 1)
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)

	const total = 200
	for i := 0; i < total; i++ {
		ctx := stickyContext(fmt.Sprintf("session-%d", i))
		first := s.Apply(ctx, a, b, c)
		second := s.Apply(ctx, c, a, b)
		if first != second {
			t.Fatalf("session %d: order changed selection %q -> %q", i, first.name, second.name)
		}
	}
}

func TestStickyHashStrategyNoClientID(t *testing.T) {
	nodes := []*stickyTestNode{
		newStickyTestNode("a", 1),
		newStickyTestNode("b", 1),
	}
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)
	for i := 0; i < 20; i++ {
		if got := s.Apply(context.Background(), nodes...); got == nil {
			t.Fatal("fallback selection is nil")
		}
	}
}

func TestStickyHashStrategySingleNode(t *testing.T) {
	node := newStickyTestNode("only", 1)
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)
	if got := s.Apply(context.Background(), node); got != node {
		t.Fatalf("selection = %v, want the only node", got)
	}
}

func TestStickyHashStrategyZeroWeight(t *testing.T) {
	nodes := []*stickyTestNode{
		newStickyTestNode("zero", 0),
		newStickyTestNode("one", 1),
	}
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		seen[s.Apply(stickyContext(fmt.Sprintf("session-%d", i)), nodes...).name] = true
	}
	if !seen["zero"] || !seen["one"] {
		t.Fatalf("zero weight should behave as 1, seen = %v", seen)
	}
}

func TestStickyHashStrategyEmptyNodes(t *testing.T) {
	s := StickyHashStrategy[*stickyTestNode](stickyNodeKey)
	if got := s.Apply(stickyContext("session")); got != nil {
		t.Fatalf("empty nodes selected %v", got)
	}
}

var _ selector.Strategy[*stickyTestNode] = StickyHashStrategy[*stickyTestNode](stickyNodeKey)
