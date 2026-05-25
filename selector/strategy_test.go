package selector

import (
	"context"
	"hash/crc32"
	"sync"
	"testing"

	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/selector"
	xctx "github.com/go-gost/x/ctx"
	xmd "github.com/go-gost/x/metadata"
)

// --- RoundRobinStrategy ---

func TestRoundRobinStrategy_Empty(t *testing.T) {
	s := RoundRobinStrategy[int]()
	if v := s.Apply(context.Background()); v != 0 {
		t.Fatalf("expected zero value, got %d", v)
	}
}

func TestRoundRobinStrategy_Single(t *testing.T) {
	s := RoundRobinStrategy[int]()
	for i := 0; i < 5; i++ {
		if v := s.Apply(context.Background(), 42); v != 42 {
			t.Fatalf("iteration %d: expected 42, got %d", i, v)
		}
	}
}

func TestRoundRobinStrategy_Sequence(t *testing.T) {
	s := RoundRobinStrategy[int]()
	items := []int{10, 20, 30}

	// Should cycle through 10, 20, 30, 10, 20, 30, ...
	for i := 0; i < 9; i++ {
		v := s.Apply(context.Background(), items...)
		expected := items[i%3]
		if v != expected {
			t.Fatalf("iteration %d: expected %d, got %d", i, expected, v)
		}
	}
}

func TestRoundRobinStrategy_Concurrent(t *testing.T) {
	s := RoundRobinStrategy[int]()
	items := []int{0, 1, 2, 3, 4}
	const goroutines = 100

	var wg sync.WaitGroup
	results := make(chan int, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.Apply(context.Background(), items...)
		}()
	}
	wg.Wait()
	close(results)

	// Every result should be a valid item
	for v := range results {
		if v < 0 || v > 4 {
			t.Fatalf("unexpected value %d", v)
		}
	}
}

// --- FIFOStrategy ---

func TestFIFOStrategy_Empty(t *testing.T) {
	s := FIFOStrategy[string]()
	if v := s.Apply(context.Background()); v != "" {
		t.Fatalf("expected zero value, got %q", v)
	}
}

func TestFIFOStrategy_AlwaysFirst(t *testing.T) {
	s := FIFOStrategy[int]()
	for i := 0; i < 10; i++ {
		v := s.Apply(context.Background(), 100, 200, 300)
		if v != 100 {
			t.Fatalf("iteration %d: expected 100, got %d", i, v)
		}
	}
}

// --- RandomStrategy ---

func TestRandomStrategy_Empty(t *testing.T) {
	s := RandomStrategy[int]()
	if v := s.Apply(context.Background()); v != 0 {
		t.Fatalf("expected zero value, got %d", v)
	}
}

func TestRandomStrategy_Single(t *testing.T) {
	s := RandomStrategy[int]()
	for i := 0; i < 10; i++ {
		if v := s.Apply(context.Background(), 7); v != 7 {
			t.Fatalf("expected 7, got %d", v)
		}
	}
}

func TestRandomStrategy_Distribution(t *testing.T) {
	s := RandomStrategy[int]()
	items := []int{0, 1, 2}
	counts := make(map[int]int)
	const n = 3000

	for i := 0; i < n; i++ {
		v := s.Apply(context.Background(), items...)
		counts[v]++
	}

	// With uniform weights, each should get roughly n/3
	for _, item := range items {
		if counts[item] < n/len(items)/2 {
			t.Fatalf("item %d underrepresented: %d/%d", item, counts[item], n)
		}
	}
}

// weightedItem implements metadata.Metadatable for weight testing.
type weightedItem struct {
	md metadata.Metadata
}

func (w *weightedItem) Metadata() metadata.Metadata { return w.md }

func TestRandomStrategy_Weighted(t *testing.T) {
	s := RandomStrategy[*weightedItem]()
	heavy := &weightedItem{md: xmd.NewMetadata(map[string]any{"weight": 100})}
	light := &weightedItem{md: xmd.NewMetadata(map[string]any{"weight": 1})}

	heavyCount := 0
	const n = 2000
	for i := 0; i < n; i++ {
		v := s.Apply(context.Background(), heavy, light)
		if v == heavy {
			heavyCount++
		}
	}

	// Heavy should win ~99% of the time with weight 100 vs 1
	if heavyCount < int(float64(n)*0.9) {
		t.Fatalf("heavy item underrepresented: %d/%d", heavyCount, n)
	}
}

func TestRandomStrategy_ZeroWeight(t *testing.T) {
	s := RandomStrategy[int]()
	// Zero/negative weights default to 1, so all items should be selectable
	v := s.Apply(context.Background(), 1, 2, 3)
	if v < 1 || v > 3 {
		t.Fatalf("expected 1-3, got %d", v)
	}
}

// --- HashStrategy ---

func TestHashStrategy_Empty(t *testing.T) {
	s := HashStrategy[int]()
	if v := s.Apply(context.Background()); v != 0 {
		t.Fatalf("expected zero value, got %d", v)
	}
}

func TestHashStrategy_ClientID(t *testing.T) {
	s := HashStrategy[int]()
	items := []int{10, 20, 30, 40, 50}
	ctx := xctx.ContextWithClientID(context.Background(), "test-client")

	// Same client ID should always map to the same item
	v1 := s.Apply(ctx, items...)
	v2 := s.Apply(ctx, items...)
	if v1 != v2 {
		t.Fatalf("hash strategy should be deterministic for same client ID: %d != %d", v1, v2)
	}

	// Verify it matches manual CRC32 calculation
	expectedIdx := uint64(crc32.ChecksumIEEE([]byte("test-client"))) % uint64(len(items))
	if v1 != items[expectedIdx] {
		t.Fatalf("expected items[%d]=%d, got %d", expectedIdx, items[expectedIdx], v1)
	}
}

func TestHashStrategy_HashSource(t *testing.T) {
	s := HashStrategy[int]()
	items := []int{10, 20, 30}
	ctx := xctx.ContextWithHash(context.Background(), &xctx.Hash{Source: "my-hash-key"})

	v1 := s.Apply(ctx, items...)
	v2 := s.Apply(ctx, items...)
	if v1 != v2 {
		t.Fatalf("hash strategy should be deterministic for same hash source: %d != %d", v1, v2)
	}
}

func TestHashStrategy_ClientIDPriorityOverHash(t *testing.T) {
	s := HashStrategy[int]()
	items := []int{10, 20, 30, 40}

	ctxClient := xctx.ContextWithClientID(context.Background(), "clientA")
	ctxBoth := xctx.ContextWithHash(
		xctx.ContextWithClientID(context.Background(), "clientA"),
		&xctx.Hash{Source: "different-hash"},
	)

	vClient := s.Apply(ctxClient, items...)
	vBoth := s.Apply(ctxBoth, items...)

	// Client ID should take priority over hash source
	if vClient != vBoth {
		t.Fatalf("client ID should take priority: %d != %d", vClient, vBoth)
	}
}

func TestHashStrategy_FallbackRandom(t *testing.T) {
	s := HashStrategy[int]()
	items := []int{0, 1, 2}
	counts := make(map[int]int)
	const n = 3000

	for i := 0; i < n; i++ {
		v := s.Apply(context.Background(), items...)
		counts[v]++
	}

	// Without client ID or hash, falls back to random
	for _, item := range items {
		if counts[item] < n/len(items)/2 {
			t.Fatalf("item %d underrepresented in random fallback: %d/%d", item, counts[item], n)
		}
	}
}

func TestHashStrategy_DifferentClientIDs(t *testing.T) {
	s := HashStrategy[int]()
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}

	selected := make(map[int]bool)
	for i := 0; i < 100; i++ {
		ctx := xctx.ContextWithClientID(context.Background(), xctx.ClientID(string(rune('A'+i))))
		v := s.Apply(ctx, items...)
		selected[v] = true
	}

	// Different client IDs should spread across multiple items
	if len(selected) < 10 {
		t.Fatalf("expected distribution across many items, got %d unique selections", len(selected))
	}
}

// --- Interface compliance ---

func TestStrategyInterfaceCompliance(t *testing.T) {
	// Verify all strategies implement selector.Strategy
	_ = selector.Strategy[int](RoundRobinStrategy[int]())
	_ = selector.Strategy[int](RandomStrategy[int]())
	_ = selector.Strategy[int](FIFOStrategy[int]())
	_ = selector.Strategy[int](HashStrategy[int]())
	_ = selector.Strategy[int](ParallelStrategy[int]())
}
