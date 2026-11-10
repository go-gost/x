// Package stats holds aggregate limiter counters shared by the limiter
// implementations and the dashboard.
package stats

import "sync/atomic"

var enabled atomic.Bool

// Enable turns limiter counter collection on or off.
func Enable(b bool) {
	enabled.Store(b)
}

// IsEnabled reports whether limiter counter collection is on.
func IsEnabled() bool {
	return enabled.Load()
}

// Snapshot is a point-in-time copy of the limiter counters.
type Snapshot struct {
	Calls     uint64
	Allowed   uint64
	Denied    uint64
	WaitCalls uint64
	Requested uint64
	Granted   uint64
}

// Stats holds atomic aggregate counters for one limiter instance.
type Stats struct {
	calls     atomic.Uint64
	allowed   atomic.Uint64
	denied    atomic.Uint64
	waitCalls atomic.Uint64
	requested atomic.Uint64
	granted   atomic.Uint64
}

// Call records one allow attempt.
func (s *Stats) Call() {
	if s != nil && enabled.Load() {
		s.calls.Add(1)
	}
}

// Allow records one allowed attempt.
func (s *Stats) Allow() {
	if s != nil && enabled.Load() {
		s.allowed.Add(1)
	}
}

// Deny records one denied attempt.
func (s *Stats) Deny() {
	if s != nil && enabled.Load() {
		s.denied.Add(1)
	}
}

// Wait records one traffic wait call and the requested byte count.
func (s *Stats) Wait(n int) {
	if s != nil && enabled.Load() && n > 0 {
		s.waitCalls.Add(1)
		s.requested.Add(uint64(n))
	}
}

// Grant records the granted byte count.
func (s *Stats) Grant(n int) {
	if s != nil && enabled.Load() && n > 0 {
		s.granted.Add(uint64(n))
	}
}

// Snapshot returns the current counters.
func (s *Stats) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{
		Calls:     s.calls.Load(),
		Allowed:   s.allowed.Load(),
		Denied:    s.denied.Load(),
		WaitCalls: s.waitCalls.Load(),
		Requested: s.requested.Load(),
		Granted:   s.granted.Load(),
	}
}
