package stats

import (
	"sync/atomic"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
)

// Probe statistic kinds, defined here in x because core/ must stay untouched.
// Core uses 1-5; 101+ is x-private space.
const (
	KindProbeSent  stats.Kind = 101
	KindProbeAcked stats.Kind = 102
	// LAN kinds count a tun hub's peer-LAN routing: what the hub refused,
	// what it put into its table, and what it took out again. They are
	// counted by the hub's RIB, not by the packet path, because the RIB is
	// where those three decisions are actually made.
	KindLanRouted    stats.Kind = 103
	KindLanDenied    stats.Kind = 104
	KindLanWithdrawn stats.Kind = 105
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
	probeSent    atomic.Uint64
	probeAcked   atomic.Uint64
	lanRouted    atomic.Uint64
	lanDenied    atomic.Uint64
	lanWithdrawn atomic.Uint64
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
	case KindProbeSent:
		if n > 0 {
			s.probeSent.Add(uint64(n))
		}
	case KindProbeAcked:
		if n > 0 {
			s.probeAcked.Add(uint64(n))
		}
	case KindLanRouted:
		if n > 0 {
			s.lanRouted.Add(uint64(n))
		}
	case KindLanDenied:
		if n > 0 {
			s.lanDenied.Add(uint64(n))
		}
	case KindLanWithdrawn:
		if n > 0 {
			s.lanWithdrawn.Add(uint64(n))
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
	case KindProbeSent:
		return s.probeSent.Load()
	case KindProbeAcked:
		return s.probeAcked.Load()
	case KindLanRouted:
		return s.lanRouted.Load()
	case KindLanDenied:
		return s.lanDenied.Load()
	case KindLanWithdrawn:
		return s.lanWithdrawn.Load()
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
	s.probeSent.Store(0)
	s.probeAcked.Store(0)
	s.lanRouted.Store(0)
	s.lanDenied.Store(0)
	s.lanWithdrawn.Store(0)
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
