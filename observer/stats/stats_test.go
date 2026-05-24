package stats

import (
	"testing"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
)

func TestStats_Add(t *testing.T) {
	s := NewStats(false)
	st := s.(*Stats)

	s.Add(stats.KindTotalConns, 1)
	if v := st.totalConns.Load(); v != 1 {
		t.Errorf("totalConns = %d, want 1", v)
	}

	s.Add(stats.KindCurrentConns, 5)
	if v := st.currentConns.Load(); v != 5 {
		t.Errorf("currentConns = %d, want 5", v)
	}
	s.Add(stats.KindCurrentConns, -2)
	if v := st.currentConns.Load(); v != 3 {
		t.Errorf("currentConns after -2 = %d, want 3", v)
	}

	s.Add(stats.KindInputBytes, 100)
	if v := st.inputBytes.Load(); v != 100 {
		t.Errorf("inputBytes = %d, want 100", v)
	}

	s.Add(stats.KindOutputBytes, 200)
	if v := st.outputBytes.Load(); v != 200 {
		t.Errorf("outputBytes = %d, want 200", v)
	}

	s.Add(stats.KindTotalErrs, 1)
	if v := st.totalErrs.Load(); v != 1 {
		t.Errorf("totalErrs = %d, want 1", v)
	}
}

func TestStats_Add_NegativeIgnored(t *testing.T) {
	s := NewStats(false)
	st := s.(*Stats)

	s.Add(stats.KindTotalConns, -1) // ignored (n <= 0 check)
	if v := st.totalConns.Load(); v != 0 {
		t.Errorf("totalConns after -1 = %d, want 0", v)
	}

	s.Add(stats.KindTotalErrs, -1) // ignored (n <= 0 check)
	if v := st.totalErrs.Load(); v != 0 {
		t.Errorf("totalErrs after -1 = %d, want 0", v)
	}
}

func TestStats_Add_Nil(t *testing.T) {
	var s *Stats
	s.Add(stats.KindTotalConns, 1) // must not panic
}

func TestStats_Get(t *testing.T) {
	s := NewStats(false)
	st := s.(*Stats)

	st.totalConns.Store(10)
	st.currentConns.Store(3)
	st.inputBytes.Store(1000)
	st.outputBytes.Store(2000)
	st.totalErrs.Store(2)

	if v := s.Get(stats.KindTotalConns); v != 10 {
		t.Errorf("totalConns = %d, want 10", v)
	}
	if v := s.Get(stats.KindCurrentConns); v != 3 {
		t.Errorf("currentConns = %d, want 3", v)
	}
	if v := s.Get(stats.KindInputBytes); v != 1000 {
		t.Errorf("inputBytes = %d, want 1000", v)
	}
	if v := s.Get(stats.KindOutputBytes); v != 2000 {
		t.Errorf("outputBytes = %d, want 2000", v)
	}
	if v := s.Get(stats.KindTotalErrs); v != 2 {
		t.Errorf("totalErrs = %d, want 2", v)
	}
}

func TestStats_Get_Nil(t *testing.T) {
	var s *Stats
	if v := s.Get(stats.KindTotalConns); v != 0 {
		t.Errorf("nil Get should return 0, got %d", v)
	}
}

func TestStats_Get_ResetTraffic(t *testing.T) {
	s := NewStats(true)
	st := s.(*Stats)

	st.inputBytes.Store(500)
	st.outputBytes.Store(300)

	// First Get should return the value and swap to 0
	if v := s.Get(stats.KindInputBytes); v != 500 {
		t.Errorf("first Get inputBytes = %d, want 500", v)
	}
	if v := st.inputBytes.Load(); v != 0 {
		t.Errorf("inputBytes after Get = %d, want 0", v)
	}

	// Second Get should return 0
	if v := s.Get(stats.KindInputBytes); v != 0 {
		t.Errorf("second Get inputBytes = %d, want 0", v)
	}

	if v := s.Get(stats.KindOutputBytes); v != 300 {
		t.Errorf("first Get outputBytes = %d, want 300", v)
	}
	if v := st.outputBytes.Load(); v != 0 {
		t.Errorf("outputBytes after Get = %d, want 0", v)
	}

	// Non-traffic counters are unaffected by resetTraffic
	st.totalConns.Store(42)
	if v := s.Get(stats.KindTotalConns); v != 42 {
		t.Errorf("totalConns = %d, want 42", v)
	}
}

func TestStats_Reset(t *testing.T) {
	s := NewStats(false)
	st := s.(*Stats)

	st.totalConns.Store(10)
	st.currentConns.Store(5)
	st.inputBytes.Store(100)
	st.outputBytes.Store(200)
	st.totalErrs.Store(3)
	st.updated.Store(true)

	s.Reset()

	if v := st.totalConns.Load(); v != 0 {
		t.Errorf("totalConns after Reset = %d, want 0", v)
	}
	if v := st.currentConns.Load(); v != 0 {
		t.Errorf("currentConns after Reset = %d, want 0", v)
	}
	if v := st.inputBytes.Load(); v != 0 {
		t.Errorf("inputBytes after Reset = %d, want 0", v)
	}
	if v := st.outputBytes.Load(); v != 0 {
		t.Errorf("outputBytes after Reset = %d, want 0", v)
	}
	if v := st.totalErrs.Load(); v != 0 {
		t.Errorf("totalErrs after Reset = %d, want 0", v)
	}
	if st.updated.Load() {
		t.Error("updated after Reset should be false")
	}
}

func TestStats_IsUpdated(t *testing.T) {
	s := NewStats(false)
	st := s.(*Stats)

	// Initially false
	if s.IsUpdated() {
		t.Error("IsUpdated should be false initially")
	}

	st.updated.Store(true)

	// Should return true then swap to false
	if !s.IsUpdated() {
		t.Error("IsUpdated should return true after update")
	}
	if s.IsUpdated() {
		t.Error("IsUpdated should return false on second call")
	}
}

func TestStats_UnknownKind(t *testing.T) {
	s := NewStats(false)

	if v := s.Get(stats.Kind(999)); v != 0 {
		t.Errorf("unknown kind should return 0, got %d", v)
	}
	// Add with unknown kind should not panic
	s.Add(stats.Kind(999), 42)
}

func TestStatsEvent_Type(t *testing.T) {
	ev := StatsEvent{}
	if ev.Type() != observer.EventStats {
		t.Errorf("Type = %q, want %q", ev.Type(), observer.EventStats)
	}
}
