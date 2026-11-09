package dashboard

import "testing"

func moduleStats(t *testing.T, snap Snapshot, kind, name, service string) ModuleStats {
	t.Helper()
	for _, m := range snap.Modules {
		if m.Kind == kind && m.Name == name && m.Service == service {
			return m.Stats
		}
	}
	t.Fatalf("module %s/%s service=%q not found in %+v", kind, name, service, snap.Modules)
	return ModuleStats{}
}

func TestSeriesSetRegistersPerService(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	set := newSeriesSet("bypass", "direct")
	a := set.get("svc-a")
	b := set.get("svc-b")
	a.calls.Add(3)
	b.calls.Add(5)

	Flush()
	snap := Default().Snapshot()
	if got := moduleStats(t, snap, "bypass", "direct", "svc-a").Calls; got != 3 {
		t.Fatalf("svc-a calls = %d, want 3", got)
	}
	if got := moduleStats(t, snap, "bypass", "direct", "svc-b").Calls; got != 5 {
		t.Fatalf("svc-b calls = %d, want 5", got)
	}
}

func TestFlushEmitsOneErrorEventPerIncrease(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	set := newSeriesSet("resolver", "local")
	c := set.get("")
	c.calls.Add(2)
	c.errors.Add(1)

	Flush()
	Flush()
	snap := Default().Snapshot()
	if got := len(snap.Events); got != 1 {
		t.Fatalf("events = %d, want 1 after repeated flush", got)
	}

	c.errors.Add(1)
	Flush()
	if got := len(Default().Snapshot().Events); got != 2 {
		t.Fatalf("events = %d, want 2 after new error", got)
	}
}

func TestStaleSeriesSetDoesNotReRegister(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	set := newSeriesSet("bypass", "old")
	ResetState()

	set.get("svc").calls.Add(1)
	Flush()
	if got := len(Default().Snapshot().Modules); got != 0 {
		t.Fatalf("modules = %d, want 0 from a stale wrapper", got)
	}
}

func TestResetStateClearsSeries(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	set := newSeriesSet("hosts", "local")
	set.get("").calls.Add(1)
	Flush()
	if len(Default().Snapshot().Modules) != 1 {
		t.Fatal("expected one module before reset")
	}

	ResetState()
	Flush()
	if got := len(Default().Snapshot().Modules); got != 0 {
		t.Fatalf("modules after reset = %d, want 0", got)
	}
}
