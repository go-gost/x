package selector

import (
	"context"
	"testing"

	"github.com/go-gost/core/selector"
)

func TestNewSelector(t *testing.T) {
	s := NewSelector[string](RoundRobinStrategy[string]())
	if s == nil {
		t.Fatal("expected non-nil selector")
	}
}

func TestDefaultSelector_Select_Empty(t *testing.T) {
	s := NewSelector[int](RoundRobinStrategy[int]())
	if v := s.Select(context.Background()); v != 0 {
		t.Fatalf("expected zero value, got %d", v)
	}
}

func TestDefaultSelector_Select_Single(t *testing.T) {
	s := NewSelector[int](RoundRobinStrategy[int]())
	if v := s.Select(context.Background(), 42); v != 42 {
		t.Fatalf("expected 42, got %d", v)
	}
}

func TestDefaultSelector_Select_WithFilters(t *testing.T) {
	strategy := FIFOStrategy[int]()
	filter := selector.Filter[int](BackupFilter[int]())
	s := NewSelector[int](strategy, filter)

	// Without backup flag, all items pass through; FIFO picks first
	v := s.Select(context.Background(), 1, 2, 3)
	if v != 1 {
		t.Fatalf("expected 1, got %d", v)
	}
}

func TestDefaultSelector_FiltersAppliedBeforeStrategy(t *testing.T) {
	// Verify that filters narrow the list before strategy picks
	strategy := FIFOStrategy[string]()
	s := NewSelector[string](strategy, FailFilter[string](1, 0))

	// All items are non-markable, so failFilter passes them all through
	v := s.Select(context.Background(), "a", "b", "c")
	if v != "a" {
		t.Fatalf("expected 'a', got %q", v)
	}
}
