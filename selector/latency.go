package selector

import (
	"context"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/selector"
)

type latencyFilter[T any] struct {
	maxLatency time.Duration
}

// LatencyFilter filters out items whose probe result indicates failure or
// latency exceeding maxLatency. Items without a probe result are passed through
// (no instrumentation = no filtering).
func LatencyFilter[T any](maxLatency time.Duration) selector.Filter[T] {
	return &latencyFilter[T]{maxLatency: maxLatency}
}

func (f *latencyFilter[T]) Filter(ctx context.Context, vs ...T) []T {
	if len(vs) <= 1 || f.maxLatency <= 0 {
		return vs
	}
	var out []T
	for _, v := range vs {
		if reader, ok := any(v).(chain.ProbeResultReader); ok {
			r := reader.ProbeResult()
			if r != nil && (!r.Success || r.Latency > f.maxLatency) {
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

type lowestLatencyStrategy[T any] struct{}

// LowestLatencyStrategy selects the item with the lowest probe latency.
// Items without a probe result or with failed probes are deprioritized
// (placed after items with successful probes).
func LowestLatencyStrategy[T any]() selector.Strategy[T] {
	return &lowestLatencyStrategy[T]{}
}

func (s *lowestLatencyStrategy[T]) Apply(ctx context.Context, vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}

	var bestLatency time.Duration
	var bestIdx int = -1
	var fallback int = -1

	for i, item := range vs {
		reader, ok := any(item).(chain.ProbeResultReader)
		if !ok {
			if fallback < 0 {
				fallback = i
			}
			continue
		}
		r := reader.ProbeResult()
		if r == nil || !r.Success {
			if fallback < 0 {
				fallback = i
			}
			continue
		}
		if bestIdx < 0 || r.Latency < bestLatency {
			bestLatency = r.Latency
			bestIdx = i
		}
	}

	if bestIdx >= 0 {
		return vs[bestIdx]
	}
	if fallback >= 0 {
		return vs[fallback]
	}
	return vs[0]
}
