package tun

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
)

func meshTestLink(t *testing.T, key string, hub bool) (*meshLink, *meshConn) {
	t.Helper()
	linkEnd, peerEnd := newMeshPipe()
	l := newMeshLink(key, linkEnd, !hub, hub, nil)
	go l.writeLoop()
	t.Cleanup(func() { l.close(MeshCloseShutdown) })
	return l, peerEnd
}

func readMeshPacket(t *testing.T, c *meshConn) []byte {
	t.Helper()
	buf := make([]byte, MaxMessageSize)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read mesh packet: %v", err)
	}
	return buf[:n]
}

func expectNoMeshPacket(t *testing.T, c *meshConn) {
	t.Helper()
	if pkt := readMeshPacketWithin(c, 100*time.Millisecond); pkt != nil {
		t.Fatalf("unexpected packet: %x", pkt)
	}
}

func readMeshPacketWithin(c *meshConn, d time.Duration) []byte {
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, MaxMessageSize)
		n, err := c.Read(buf)
		if err != nil {
			done <- nil
			return
		}
		done <- append([]byte(nil), buf[:n]...)
	}()
	select {
	case pkt := <-done:
		return pkt
	case <-time.After(d):
		return nil
	}
}

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

func newMeshTestHandler(local ...string) *meshHandler {
	ips := make([]net.IP, 0, len(local))
	for _, s := range local {
		ips = append(ips, net.ParseIP(s))
	}
	return NewMeshHandler(MeshConfig{
		LocalKey: "local",
		HubKey:   "hub",
		LocalIPs: ips,
	}, handler.LoggerOption(compatLogger())).(*meshHandler)
}

func TestMeshDispatchDirectAndHub(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: false},
	})
	bLink, bPeer := meshTestLink(t, "b", false)
	bLink.ready.Store(true)
	h.links["b"] = bLink
	hubLink, hubPeer := meshTestLink(t, "hub", true)
	h.hub = hubLink

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	if got := readMeshPacket(t, bPeer); len(got) == 0 {
		t.Fatal("packet for B did not reach the direct link")
	}

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.3", 1, 2))
	if got := readMeshPacket(t, hubPeer); len(got) == 0 {
		t.Fatal("packet for C did not reach the hub")
	}

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.9", 1, 3))
	if got := readMeshPacket(t, hubPeer); len(got) == 0 {
		t.Fatal("packet for an unknown member did not reach the hub")
	}
}

func TestMeshDirectNeededAndFallback(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	hubLink, hubPeer := meshTestLink(t, "hub", true)
	h.hub = hubLink

	var needed []string
	h.SetDirectNeeded(func(peer string) { needed = append(needed, peer) })

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	if got := readMeshPacket(t, hubPeer); len(got) == 0 {
		t.Fatal("packet for B did not fall back to the hub")
	}
	if len(needed) == 0 || needed[0] != "b" {
		t.Fatalf("DirectNeeded = %v, want b", needed)
	}

	link, peer := meshTestLink(t, "b", false)
	h.links["b"] = link
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 2))
	if got := readMeshPacket(t, hubPeer); len(got) == 0 {
		t.Fatal("packet for a not-ready direct link did not fall back to the hub")
	}

	link.ready.Store(true)
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 3))
	if got := readMeshPacket(t, peer); len(got) == 0 {
		t.Fatal("packet for a ready direct link did not use it")
	}
}

func TestMeshBlockedMemberIsDropped(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true, Blocked: true}})
	hubLink, hubPeer := meshTestLink(t, "hub", true)
	h.hub = hubLink

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	expectNoMeshPacket(t, hubPeer)
	if h.countBlocked.Load() == 0 {
		t.Fatal("blocked counter did not move")
	}
}

func TestMeshNoHubDrops(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.9", 1, 1))
	if h.countNoRoute.Load() == 0 {
		t.Fatal("no-route counter did not move")
	}
}

func TestMeshLocalDestinationLoop(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.1", 1, 1))
	if h.countLoop.Load() == 0 {
		t.Fatal("loop counter did not move")
	}
}

func TestMeshEmptyLocalIPsDoesNotPanic(t *testing.T) {
	h := newMeshTestHandler()
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	hubLink, hubPeer := meshTestLink(t, "hub", true)
	h.hub = hubLink

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	if got := readMeshPacket(t, hubPeer); len(got) == 0 {
		t.Fatal("packet did not reach the hub with empty local IPs")
	}
}

func TestMeshNilCallbacks(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	h.SetDirectNeeded(nil)
	h.SetLinkClosed(nil)
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	hubLink, _ := meshTestLink(t, "hub", true)
	h.hub = hubLink
	h.Close()
}

func TestMeshQueueFullFallsBackToHub(t *testing.T) {
	old := meshQueueDepth
	meshQueueDepth = 1
	t.Cleanup(func() { meshQueueDepth = old })

	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})

	directEnd, directPeer := newMeshPipe()
	direct := newMeshLink("b", directEnd, true, false, nil)
	direct.ready.Store(true)
	h.links["b"] = direct
	_ = directPeer

	hubLink, hubPeer := meshTestLink(t, "hub", true)
	h.hub = hubLink

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 2))
	if got := readMeshPacket(t, hubPeer); len(got) == 0 {
		t.Fatal("second packet did not fall back to the hub")
	}
	if h.countDirectFallback.Load() == 0 {
		t.Fatal("direct-fallback counter did not move")
	}
}

func TestMeshBackpressureDoesNotBlockDeviceReader(t *testing.T) {
	old := meshQueueDepth
	meshQueueDepth = 1
	t.Cleanup(func() { meshQueueDepth = old })

	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: true},
	})

	directEnd, _ := newMeshPipe()
	direct := newMeshLink("b", directEnd, true, false, nil)
	direct.ready.Store(true)
	h.links["b"] = direct

	cEnd, cPeer := newMeshPipe()
	cLink := newMeshLink("c", cEnd, true, false, nil)
	cLink.ready.Store(true)
	go cLink.writeLoop()
	h.links["c"] = cLink

	start := time.Now()
	for i := 0; i < 100; i++ {
		h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, i))
	}
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.3", 1, 101))
	if d := time.Since(start); d > time.Second {
		t.Fatalf("dispatch blocked for %v", d)
	}
	if got := readMeshPacketWithin(cPeer, time.Second); len(got) == 0 {
		t.Fatal("a healthy direct link was starved by a blocked one")
	}
}

func TestMeshRunDeviceDispatches(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, peer := meshTestLink(t, "b", false)
	link.ready.Store(true)
	h.links["b"] = link

	dev, send, _ := newDevice()
	d := compatTunDevice{compatDevice: dev, ctx: context.Background()}
	go h.RunDevice(d)
	t.Cleanup(func() { _ = dev.Close() })

	deadline := time.Now().Add(time.Second)
	for {
		h.mu.RLock()
		ready := h.device != nil
		h.mu.RUnlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RunDevice did not attach the device")
		}
		time.Sleep(time.Millisecond)
	}

	if _, err := send.Write(udpPacket("10.0.0.1", "10.0.0.2", 1, 1)); err != nil {
		t.Fatalf("write device: %v", err)
	}
	if got := readMeshPacketWithin(peer, time.Second); len(got) == 0 {
		t.Fatal("device packet did not reach the direct link")
	}
}
