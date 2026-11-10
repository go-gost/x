package stats

import "testing"

func TestStatsGatedByEnable(t *testing.T) {
	Enable(false)
	s := &Stats{}
	s.Call()
	s.Allow()
	if got := s.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("disabled stats = %+v", got)
	}

	Enable(true)
	defer Enable(false)
	s.Call()
	s.Allow()
	s.Deny()
	s.Wait(10)
	s.Grant(7)
	got := s.Snapshot()
	if got.Calls != 1 || got.Allowed != 1 || got.Denied != 1 || got.WaitCalls != 1 || got.Requested != 10 || got.Granted != 7 {
		t.Fatalf("stats = %+v", got)
	}
}
