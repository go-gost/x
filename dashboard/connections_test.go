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

func TestConnectionsMergeSameSID(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	Default().RecordConnection(ConnectionRecord{
		SID: "x", Service: "svc", BytesIn: 56, BytesOut: 55, DurationMs: 1, Time: "2026-11-15T00:00:00Z",
	})
	Default().RecordConnection(ConnectionRecord{
		SID: "x", Service: "svc", Path: []PathHop{{Chain: "chain-0", Hop: 0, Node: "n0", Addr: "127.0.0.1:9", ConnectMs: 1, Err: "dial"}},
		Chain: "chain-0", Err: "dial tcp x", Time: "2026-11-15T00:00:01Z",
	})
	got := Default().Connections(0, "", "")
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Chain != "chain-0" || len(got[0].Path) != 1 || got[0].Err != "dial tcp x" {
		t.Fatalf("merge kept wrong fields: %+v", got[0])
	}
	if got[0].BytesIn != 56 {
		t.Fatalf("bytes lost: %+v", got[0])
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
		rec := records(1)[0]
		rec.SID = string(rune('a' + i))
		Default().RecordConnection(rec)
	}
	got := Default().Connections(10000, "", "")
	if len(got) != 10 {
		t.Fatalf("got %d", len(got))
	}
}

func TestConnectionsRecordSeriesAreClonedOnRead(t *testing.T) {
	ResetState()
	defer ResetState()
	Enable(true)
	defer Enable(false)

	Default().RecordConnection(ConnectionRecord{
		SID: "s1", Service: "svc", Path: []PathHop{{Chain: "c", Hop: 0, Node: "n"}},
	})

	snap := Default().Connections(10, "", "")
	if len(snap) != 1 {
		t.Fatalf("records = %d, want 1", len(snap))
	}
	snap[0].Path[0].Chain = "mutated"

	snap2 := Default().Connections(10, "", "")
	if snap2[0].Path[0].Chain != "c" {
		t.Fatalf("ring mutated through snapshot: %q", snap2[0].Path[0].Chain)
	}
}
