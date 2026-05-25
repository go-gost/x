package selector

import (
	"testing"
)

func TestRandomWeighted_Empty(t *testing.T) {
	rw := NewRandomWeighted[int]()
	if v := rw.Next(); v != 0 {
		t.Fatalf("expected zero value, got %d", v)
	}
}

func TestRandomWeighted_Single(t *testing.T) {
	rw := NewRandomWeighted[int]()
	rw.Add(42, 10)
	for i := 0; i < 100; i++ {
		if v := rw.Next(); v != 42 {
			t.Fatalf("expected 42, got %d", v)
		}
	}
}

func TestRandomWeighted_EqualWeights(t *testing.T) {
	rw := NewRandomWeighted[int]()
	rw.Add(1, 1)
	rw.Add(2, 1)
	rw.Add(3, 1)

	counts := make(map[int]int)
	const n = 3000
	for i := 0; i < n; i++ {
		counts[rw.Next()]++
	}

	for _, item := range []int{1, 2, 3} {
		if counts[item] < n/3/2 {
			t.Fatalf("item %d underrepresented: %d/%d", item, counts[item], n)
		}
	}
}

func TestRandomWeighted_WeightedDistribution(t *testing.T) {
	rw := NewRandomWeighted[string]()
	rw.Add("heavy", 99)
	rw.Add("light", 1)

	heavyCount := 0
	const n = 5000
	for i := 0; i < n; i++ {
		if rw.Next() == "heavy" {
			heavyCount++
		}
	}

	// ~99% should be heavy
	if heavyCount < int(float64(n)*0.95) {
		t.Fatalf("heavy underrepresented: %d/%d", heavyCount, n)
	}
}

func TestRandomWeighted_ZeroWeight(t *testing.T) {
	rw := NewRandomWeighted[int]()
	rw.Add(1, 0)
	rw.Add(2, 0)
	// sum=0, should return zero value
	if v := rw.Next(); v != 0 {
		t.Fatalf("expected zero value with sum=0, got %d", v)
	}
}

func TestRandomWeighted_Reset(t *testing.T) {
	rw := NewRandomWeighted[int]()
	rw.Add(1, 10)
	rw.Add(2, 20)

	rw.Reset()
	if v := rw.Next(); v != 0 {
		t.Fatalf("expected zero value after reset, got %d", v)
	}

	// Can add again after reset
	rw.Add(3, 1)
	if v := rw.Next(); v != 3 {
		t.Fatalf("expected 3 after re-add, got %d", v)
	}
}

func TestRandomWeighted_MultipleWeights(t *testing.T) {
	rw := NewRandomWeighted[int]()
	rw.Add(0, 1)
	rw.Add(1, 2)
	rw.Add(2, 3)
	// Total weight = 6

	counts := make(map[int]int)
	const n = 6000
	for i := 0; i < n; i++ {
		counts[rw.Next()]++
	}

	// Item 2 should appear roughly 2x more than item 0
	ratio := float64(counts[2]) / float64(counts[0])
	if ratio < 1.5 || ratio > 3.5 {
		t.Fatalf("expected ratio ~2.0 for item2/item0, got %.2f (counts: %v)", ratio, counts)
	}
}

func TestRandomWeighted_StringItems(t *testing.T) {
	rw := NewRandomWeighted[string]()
	rw.Add("a", 1)
	rw.Add("b", 1)

	v := rw.Next()
	if v != "a" && v != "b" {
		t.Fatalf("expected 'a' or 'b', got %q", v)
	}
}

func TestRandomWeighted_StructItems(t *testing.T) {
	type item struct{ Name string }
	rw := NewRandomWeighted[item]()
	rw.Add(item{Name: "x"}, 1)
	rw.Add(item{Name: "y"}, 1)

	v := rw.Next()
	if v.Name != "x" && v.Name != "y" {
		t.Fatalf("unexpected item: %+v", v)
	}
}
