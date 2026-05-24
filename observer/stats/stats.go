package stats

import (
	"sync/atomic"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
)

// Stats implements the stats.Stats interface using atomic counters.
// When resetTraffic is true, Get for KindInputBytes and KindOutputBytes
// atomically swaps the counter with zero, returning the value at the time
// of the call.
type Stats struct {
	updated      atomic.Bool
	totalConns   atomic.Uint64
	currentConns atomic.Uint64
	inputBytes   atomic.Uint64
	outputBytes  atomic.Uint64
	totalErrs    atomic.Uint64
	resetTraffic bool
}

// NewStats creates a new Stats instance. When resetTraffic is true, calls
// to Get for KindInputBytes and KindOutputBytes atomically reset the counter
// to zero after reading, which is useful for rate calculations.
func NewStats(resetTraffic bool) stats.Stats {
	return &Stats{
		resetTraffic: resetTraffic,
	}
}

func (s *Stats) Add(kind stats.Kind, n int64) {
	if s == nil {
		return
	}
	switch kind {
	case stats.KindTotalConns:
		if n > 0 {
			s.totalConns.Add(uint64(n))
		}
	case stats.KindCurrentConns:
		s.currentConns.Add(uint64(n))
	case stats.KindInputBytes:
		s.inputBytes.Add(uint64(n))
	case stats.KindOutputBytes:
		s.outputBytes.Add(uint64(n))
	case stats.KindTotalErrs:
		if n > 0 {
			s.totalErrs.Add(uint64(n))
		}
	}
	s.updated.Store(true)
}

func (s *Stats) Get(kind stats.Kind) uint64 {
	if s == nil {
		return 0
	}

	switch kind {
	case stats.KindTotalConns:
		return s.totalConns.Load()
	case stats.KindCurrentConns:
		return s.currentConns.Load()
	case stats.KindInputBytes:
		if s.resetTraffic {
			return s.inputBytes.Swap(0)
		}
		return s.inputBytes.Load()
	case stats.KindOutputBytes:
		if s.resetTraffic {
			return s.outputBytes.Swap(0)
		}
		return s.outputBytes.Load()
	case stats.KindTotalErrs:
		return s.totalErrs.Load()
	}
	return 0
}

func (s *Stats) Reset() {
	s.updated.Store(false)
	s.totalConns.Store(0)
	s.currentConns.Store(0)
	s.inputBytes.Store(0)
	s.outputBytes.Store(0)
	s.totalErrs.Store(0)
}

func (s *Stats) IsUpdated() bool {
	return s.updated.Swap(false)
}

// StatsEvent carries a snapshot of all tracked statistics for a specific
// service and optional client. It implements observer.Event.
type StatsEvent struct {
	Kind    string
	Service string
	Client  string

	TotalConns   uint64
	CurrentConns uint64
	InputBytes   uint64
	OutputBytes  uint64
	TotalErrs    uint64
}

// Type returns observer.EventStats to identify this as a statistics event.
func (StatsEvent) Type() observer.EventType {
	return observer.EventStats
}
