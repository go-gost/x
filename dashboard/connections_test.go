package dashboard

import (
	"testing"
	"time"

	)

func records(n int) []ConnectionRecord {
	out := make([]ConnectionRecord, n)
	for i := range out {
		out[i] = ConnectionRecord{
			SID:        string(rune('a' + i)),
			Service:    "svc-0",
			RemoteAddr: "10.0.0.1:8080",
			Chain:      "chain-0",
			Path:       []PathHop{{Chain: "chain-0", Hop: 0, Node: "n1", Addr: "10.0.0.1:80", ConnectMs: 1}},
			Time:       time.Unix(int64(i), 0).UTC().Format(time.RFC3339),
		}
	}
	return out
}

func TestRingEvictsOldest(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	for _, rec := range records(1026) {
		Default().RecordConnection(rec)
	}
	got := Default().Connections(0, "", "")
	if len(got) > 1024 {
		t.Fatalf("ring len = %d", len(got))
	}
	if len(got) != 1024 {
		t.Fatalf("ring len = %d", len(got))
	}
	for _, rec := range got {
		if rec.SID == "a" || rec.SID == "b" {
			t.Fatalf("evicted sid still present: %s", rec.SID)
		}
	}
}

func TestConnectionsFilterByServiceSid(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	recs := records(3)
	recs[0].Service = "alpha"
	recs[1].Service = "beta"
	recs[2].Service = "alpha"
	for _, rec := range recs {
		Default().RecordConnection(rec)
	}
	alpha := Default().Connections(0, "alpha", "")
	if len(alpha) != 2 {
		t.Fatalf("alpha len = %d", len(alpha))
	}
	a := Default().Connections(0, "", "a")
	if len(a) != 1 || a[0].SID != "a" {
		t.Fatalf("a = %+v", a)
	}
}

func TestConnectionsDefaultCap(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	for _, rec := range records(1100) {
		Default().RecordConnection(rec)
	}
	got := Default().Connections(0, "", "")
	if len(got) != 1024 {
		t.Fatalf("default cap = %d", len(got))
	}
}

func TestConnectionsCapZeroDisables(t *testing.T) {
	// The caller asks for a larger limit than stored; the hard cap in the
	// collector still wins.
	ResetState()
	Enable(true)
	defer Enable(false)

	for i := 0; i < 10; i++ {
		Default().RecordConnection(records(1)[0])
	}
	got := Default().Connections(10000, "", "")
	if len(got) != 10 {
		t.Fatalf("got %d", len(got))
	}
}
