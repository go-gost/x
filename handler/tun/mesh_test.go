package tun

import (
	"net"
	"testing"

	"github.com/go-gost/core/handler"
)

func TestMeshSetMembersStatus(t *testing.T) {
	h := NewMeshHandler(MeshConfig{
		LocalKey: "local",
		HubKey:   "hub",
		LocalIPs: []net.IP{net.ParseIP("10.0.0.1")},
	}, handler.LoggerOption(compatLogger())).(*meshHandler)

	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Name: "B", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: true, Blocked: true},
		{IP: net.ParseIP("10.0.0.4"), Key: "d", Direct: false},
	})

	st := h.MeshStatus()
	if len(st) != 4 {
		t.Fatalf("MeshStatus = %d rows, want 4: %+v", len(st), st)
	}
	if st[0].Key != "hub" || st[0].State != "hub" {
		t.Fatalf("first row = %+v, want the hub row", st[0])
	}
	byKey := make(map[string]MeshPeerStatus, len(st))
	for _, row := range st {
		byKey[row.Key] = row
	}
	if got := byKey["b"]; got.Name != "B" || got.State != "hub" {
		t.Fatalf("b row = %+v, want name B, state hub", got)
	}
	if got := byKey["c"]; got.State != "blocked" {
		t.Fatalf("c row = %+v, want blocked", got)
	}
	if got := byKey["d"]; got.State != "direct-off" {
		t.Fatalf("d row = %+v, want direct-off", got)
	}

	h.SetMembers(nil)
	st = h.MeshStatus()
	if len(st) != 1 || st[0].Key != "hub" {
		t.Fatalf("MeshStatus after nil members = %+v, want only the hub row", st)
	}
}

func TestMeshCloseIsIdempotent(t *testing.T) {
	h := NewMeshHandler(MeshConfig{}, handler.LoggerOption(compatLogger()))
	if err := h.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
