package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
)

func silenceMeshPanicLogs(t *testing.T) {
	t.Helper()
	oldLink, oldDevice := meshLinkPanicLog, meshDevicePanicLog
	meshLinkPanicLog = func(string, string, any) {}
	meshDevicePanicLog = func(string, any) {}
	t.Cleanup(func() {
		meshLinkPanicLog, meshDevicePanicLog = oldLink, oldDevice
	})
}

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

func attachMeshDevice(t *testing.T, h *meshHandler) *datagramPipe {
	t.Helper()
	dev, _, recv := newDevice()
	d := compatTunDevice{compatDevice: dev, ctx: context.Background()}
	h.mu.Lock()
	h.device = d
	h.mu.Unlock()
	t.Cleanup(func() {
		h.mu.Lock()
		if h.device == d {
			h.device = nil
		}
		h.mu.Unlock()
		_ = dev.Close()
	})
	return recv
}

func readDevicePacketWithin(recv *datagramPipe, d time.Duration) []byte {
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, MaxMessageSize)
		n, err := recv.Read(buf)
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

func TestMeshAddDialedLinkWrites(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	h.AddDialedLink("b", linkEnd)

	reg := readMeshPacket(t, peer)
	if !isRegistrationFrame(reg) {
		t.Fatalf("first write = %x, want a registration frame", reg)
	}
	if _, err := peer.Write(bytes.Repeat([]byte{0x47}, keepAliveHeaderLength)); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	if _, err := peer.Write(udpPacket("10.0.0.2", "10.0.0.1", 1, 1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if got := readDevicePacketWithin(recv, time.Second); len(got) == 0 {
		t.Fatal("direct packet did not reach the device")
	}
	h.Close()
}

func TestMeshAddDialedLinkRejects(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true, Blocked: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: true, Disabled: true},
		{IP: net.ParseIP("10.0.0.4"), Key: "d", Direct: false},
	})
	cases := []string{"unknown", "hub", "local", "b", "c", "d"}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			linkEnd, peer := newMeshPipe()
			h.AddDialedLink(key, linkEnd)
			h.mu.RLock()
			link := h.links[key]
			h.mu.RUnlock()
			if link != nil {
				t.Fatalf("link for rejected peer %q was installed", key)
			}
			_ = peer.Close()
		})
	}
}

func TestMeshHandleInbound(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	linkEnd.remote = "b"
	errCh := make(chan error, 1)
	go func() { errCh <- h.Handle(context.Background(), linkEnd) }()

	if _, err := peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2"))); err != nil {
		t.Fatalf("write registration: %v", err)
	}
	if got := readMeshPacketWithin(peer, time.Second); len(got) == 0 {
		t.Fatal("registration was not echoed")
	}
	if _, err := peer.Write(udpPacket("10.0.0.2", "10.0.0.1", 1, 1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if got := readDevicePacketWithin(recv, time.Second); len(got) == 0 {
		t.Fatal("inbound direct packet did not reach the device")
	}

	_ = peer.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle did not return after the stream closed")
	}
}

func TestMeshHandleRejectsNonTunFirstFrame(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})

	linkEnd, peer := newMeshPipe()
	linkEnd.remote = "b"
	errCh := make(chan error, 1)
	go func() { errCh <- h.Handle(context.Background(), linkEnd) }()
	if _, err := peer.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle did not return for a non-tun first frame")
	}
	h.mu.RLock()
	_, installed := h.links["b"]
	h.mu.RUnlock()
	if installed {
		t.Fatal("non-tun stream was installed")
	}
}

func TestMeshHandleRejectsWrongSource(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	linkEnd.remote = "b"
	go h.Handle(context.Background(), linkEnd)
	_, _ = peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2")))
	_ = readMeshPacketWithin(peer, time.Second)
	_, _ = peer.Write(udpPacket("10.0.0.3", "10.0.0.1", 1, 1))
	expectNoDevicePacket(t, recv)
	if h.countForeignSrc.Load() == 0 {
		t.Fatal("foreign-source counter did not move")
	}
	_ = peer.Close()
}

func TestMeshHandleRejectsForeignDestination(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: true},
	})
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	linkEnd.remote = "b"
	go h.Handle(context.Background(), linkEnd)
	_, _ = peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2")))
	_ = readMeshPacketWithin(peer, time.Second)
	_, _ = peer.Write(udpPacket("10.0.0.2", "10.0.0.3", 1, 1))
	expectNoDevicePacket(t, recv)
	if h.countForeignDst.Load() == 0 {
		t.Fatal("foreign-destination counter did not move")
	}
	_ = peer.Close()
}

func TestMeshHandleNeverForwardsToPeer(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: true},
	})
	recv := attachMeshDevice(t, h)
	cLink, cPeer := meshTestLink(t, "c", false)
	cLink.ready.Store(true)
	h.links["c"] = cLink

	linkEnd, peer := newMeshPipe()
	linkEnd.remote = "b"
	go h.Handle(context.Background(), linkEnd)
	_, _ = peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2")))
	_ = readMeshPacketWithin(peer, time.Second)
	_, _ = peer.Write(udpPacket("10.0.0.2", "10.0.0.3", 1, 1))
	expectNoDevicePacket(t, recv)
	expectNoMeshPacket(t, cPeer)
	_ = peer.Close()
}

func TestMeshHubFrameWritesDevice(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	h.SetHubLink(linkEnd)
	_ = readMeshPacket(t, peer) // registration
	if _, err := peer.Write(udpPacket("10.0.0.9", "10.0.0.1", 1, 1)); err != nil {
		t.Fatalf("write hub packet: %v", err)
	}
	if got := readDevicePacketWithin(recv, time.Second); len(got) == 0 {
		t.Fatal("hub packet did not reach the device")
	}
	h.Close()
}

func TestMeshInvalidRegistrationCloses(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "c", Direct: true},
	})
	closed := make(chan MeshCloseReason, 1)
	h.SetLinkClosed(func(peer string, reason MeshCloseReason) {
		if peer == "b" {
			select {
			case closed <- reason:
			default:
			}
		}
	})

	linkEnd, peer := newMeshPipe()
	h.AddDialedLink("b", linkEnd)
	_ = readMeshPacket(t, peer) // our registration
	if _, err := peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.3"))); err != nil {
		t.Fatalf("write bad registration: %v", err)
	}
	select {
	case reason := <-closed:
		if reason != MeshCloseMembership {
			t.Fatalf("close reason = %q, want membership", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("link did not close after an invalid registration")
	}
}

func expectNoDevicePacket(t *testing.T, recv *datagramPipe) {
	t.Helper()
	if got := readDevicePacketWithin(recv, 100*time.Millisecond); got != nil {
		t.Fatalf("unexpected device packet: %x", got)
	}
}

func meshLinkFor(t *testing.T, h *meshHandler, key string, dialed bool) (*meshLink, *meshConn) {
	t.Helper()
	linkEnd, peer := newMeshPipe()
	l := newMeshLink(key, linkEnd, dialed, false, func(l *meshLink, reason MeshCloseReason) {
		h.removeLink(l, reason, false)
	})
	t.Cleanup(func() { l.close(MeshCloseShutdown) })
	return l, peer
}

func TestMeshDedupePrefersSmallerDialer(t *testing.T) {
	h := NewMeshHandler(MeshConfig{LocalKey: "a", HubKey: "hub"}, handler.LoggerOption(compatLogger())).(*meshHandler)
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	closed := make(chan MeshCloseReason, 2)
	h.SetLinkClosed(func(peer string, reason MeshCloseReason) {
		if peer == "b" {
			closed <- reason
		}
	})

	out, _ := meshLinkFor(t, h, "b", true)
	in, _ := meshLinkFor(t, h, "b", false)
	if !h.installLink(out) {
		t.Fatal("outbound link (dialer a) lost")
	}
	if h.installLink(in) {
		t.Fatal("inbound link (dialer b) won; want the smaller dialer")
	}
	h.mu.RLock()
	got := h.links["b"]
	h.mu.RUnlock()
	if got != out {
		t.Fatal("the outbound link is not the current link")
	}
	select {
	case reason := <-closed:
		if reason != MeshCloseDedup {
			t.Fatalf("close reason = %q, want dedup", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("dedup close was not reported")
	}
}

func TestMeshDedupeEqualKeepsExisting(t *testing.T) {
	h := NewMeshHandler(MeshConfig{LocalKey: "b", HubKey: "hub"}, handler.LoggerOption(compatLogger())).(*meshHandler)
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	first, _ := meshLinkFor(t, h, "b", true)
	second, _ := meshLinkFor(t, h, "b", false)
	if !h.installLink(first) {
		t.Fatal("first link lost")
	}
	if h.installLink(second) {
		t.Fatal("equal-dialer incoming link won; want the existing link")
	}
	h.mu.RLock()
	got := h.links["b"]
	h.mu.RUnlock()
	if got != first {
		t.Fatal("the existing link was not kept")
	}
}

func TestMeshDedupeLargerDialerOnly(t *testing.T) {
	h := NewMeshHandler(MeshConfig{LocalKey: "z", HubKey: "hub"}, handler.LoggerOption(compatLogger())).(*meshHandler)
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	in, _ := meshLinkFor(t, h, "b", false)
	out, _ := meshLinkFor(t, h, "b", true)
	if !h.installLink(in) {
		t.Fatal("inbound link (dialer b) lost")
	}
	if h.installLink(out) {
		t.Fatal("outbound link (dialer z) won; want the smaller dialer")
	}
	h.mu.RLock()
	got := h.links["b"]
	h.mu.RUnlock()
	if got != in {
		t.Fatal("the inbound link is not the current link")
	}
}

func TestMeshMembershipRemovalClosesLink(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, _ := meshLinkFor(t, h, "b", true)
	h.installLink(link)
	closed := make(chan MeshCloseReason, 1)
	h.SetLinkClosed(func(peer string, reason MeshCloseReason) {
		if peer == "b" {
			closed <- reason
		}
	})

	h.SetMembers(nil)
	select {
	case reason := <-closed:
		if reason != MeshCloseMembership {
			t.Fatalf("close reason = %q, want membership", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("link did not close after membership removal")
	}
}

func TestMeshBlockedMemberClosesLink(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, _ := meshLinkFor(t, h, "b", true)
	h.installLink(link)
	closed := make(chan MeshCloseReason, 1)
	h.SetLinkClosed(func(peer string, reason MeshCloseReason) {
		if peer == "b" {
			closed <- reason
		}
	})

	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true, Blocked: true}})
	select {
	case reason := <-closed:
		if reason != MeshCloseBlocked {
			t.Fatalf("close reason = %q, want blocked", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("link did not close after block")
	}
}

func TestMeshStatusAfterLinks(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Name: "B", Direct: true}})
	link, _ := meshLinkFor(t, h, "b", true)
	link.ready.Store(true)
	link.bytesIn.Store(11)
	link.bytesOut.Store(22)
	h.installLink(link)
	hubLink, _ := meshTestLink(t, "hub", true)
	h.hub = hubLink

	st := h.MeshStatus()
	var b MeshPeerStatus
	for _, row := range st {
		if row.Key == "b" {
			b = row
		}
	}
	if b.State != "direct" || !b.DialedLocally || b.Name != "B" {
		t.Fatalf("b row = %+v, want direct/dialed/B", b)
	}
	if b.BytesIn != 11 || b.BytesOut != 22 {
		t.Fatalf("b bytes = %d/%d, want 11/22", b.BytesIn, b.BytesOut)
	}
	if st[0].Key != "hub" {
		t.Fatalf("first row = %+v, want hub", st[0])
	}
}

func TestMeshHubLinkCloseCallback(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	closed := make(chan MeshCloseReason, 1)
	h.SetLinkClosed(func(peer string, reason MeshCloseReason) {
		if peer == "hub" {
			closed <- reason
		}
	})
	linkEnd, peer := newMeshPipe()
	h.SetHubLink(linkEnd)
	_ = readMeshPacket(t, peer)
	_ = peer.Close()
	select {
	case reason := <-closed:
		if reason != MeshCloseRemote {
			t.Fatalf("hub close reason = %q, want remote", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("hub close was not reported")
	}
	h.mu.RLock()
	got := h.hub
	h.mu.RUnlock()
	if got != nil {
		t.Fatal("closed hub link is still installed")
	}
}

func TestMeshShutdownDoesNotRedial(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	var calls atomic.Int32
	h.SetLinkClosed(func(string, MeshCloseReason) { calls.Add(1) })
	linkEnd, peer := newMeshPipe()
	h.SetHubLink(linkEnd)
	_ = readMeshPacket(t, peer)
	h.Close()
	if got := calls.Load(); got != 0 {
		t.Fatalf("shutdown reported %d link closes, want 0", got)
	}
}

func waitForMeshDevice(t *testing.T, h *meshHandler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		h.mu.RLock()
		ready := h.device != nil
		h.mu.RUnlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("RunDevice did not attach the device")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMeshDeviceReplacement(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, peer := meshTestLink(t, "b", false)
	link.ready.Store(true)
	h.links["b"] = link

	dev1, send1, _ := newDevice()
	d1 := compatTunDevice{compatDevice: dev1, ctx: context.Background()}
	done1 := make(chan error, 1)
	go func() { done1 <- h.RunDevice(d1) }()
	waitForMeshDevice(t, h)

	if _, err := send1.Write(udpPacket("10.0.0.1", "10.0.0.2", 1, 1)); err != nil {
		t.Fatalf("write dev1: %v", err)
	}
	if got := readMeshPacketWithin(peer, time.Second); len(got) == 0 {
		t.Fatal("dev1 packet did not reach the direct link")
	}
	_ = dev1.Close()
	<-done1

	dev2, send2, _ := newDevice()
	d2 := compatTunDevice{compatDevice: dev2, ctx: context.Background()}
	done2 := make(chan error, 1)
	go func() { done2 <- h.RunDevice(d2) }()
	waitForMeshDevice(t, h)
	t.Cleanup(func() { _ = dev2.Close(); <-done2 })

	if _, err := send2.Write(udpPacket("10.0.0.1", "10.0.0.2", 1, 2)); err != nil {
		t.Fatalf("write dev2: %v", err)
	}
	if got := readMeshPacketWithin(peer, time.Second); len(got) == 0 {
		t.Fatal("dev2 packet did not reach the direct link")
	}
	h.mu.RLock()
	still := h.links["b"] == link
	h.mu.RUnlock()
	if !still {
		t.Fatal("the direct link did not survive device replacement")
	}
}

func TestMeshLateDeviceWriteAfterClose(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	attachMeshDevice(t, h)
	h.Close()
	if err := h.writeDevice([]byte{0x45, 0, 0, 20}); !errors.Is(err, ErrTun) {
		t.Fatalf("writeDevice after Close = %v, want ErrTun", err)
	}
}

type meshRecorderDevice struct {
	*writeRecorder
}

func (d meshRecorderDevice) LocalAddr() net.Addr         { return peerAddr{"recorder", ""} }
func (d meshRecorderDevice) RemoteAddr() net.Addr        { return peerAddr{"recorder", ""} }
func (d meshRecorderDevice) SetDeadline(time.Time) error { return nil }
func (d meshRecorderDevice) SetReadDeadline(time.Time) error {
	return nil
}
func (d meshRecorderDevice) SetWriteDeadline(time.Time) error { return nil }
func (d meshRecorderDevice) Close() error                     { return nil }

func TestMeshConcurrentDeviceWrites(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	rec := newWriteRecorder(MaxMessageSize)
	h.mu.Lock()
	h.device = meshRecorderDevice{writeRecorder: rec}
	h.mu.Unlock()

	pkt := udpPacket("10.0.0.2", "10.0.0.1", 1, 1)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.writeDevice(pkt)
		}()
	}
	wg.Wait()
	if got := rec.overlapping(); got != 0 {
		t.Fatalf("device writes overlapped %d times", got)
	}
	if got := len(rec.received()); got != 32 {
		t.Fatalf("device received %d writes, want 32", got)
	}
}

type panicReadConn struct{ *meshConn }

func (c panicReadConn) Read([]byte) (int, error) { panic("device read boom") }

func TestMeshRunDevicePanic(t *testing.T) {
	silenceMeshPanicLogs(t)
	h := newMeshTestHandler("10.0.0.1")
	linkEnd, peer := newMeshPipe()
	err := h.RunDevice(panicReadConn{meshConn: linkEnd})
	if err == nil {
		t.Fatal("RunDevice returned nil after a panicking device read")
	}
	_ = peer.Close()
}

func TestMeshDirectSurvivesDeviceGap(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})

	linkEnd, peer := newMeshPipe()
	h.AddDialedLink("b", linkEnd)
	_ = readMeshPacket(t, peer)
	_, _ = peer.Write(bytes.Repeat([]byte{0x47}, keepAliveHeaderLength))
	deadline := time.Now().Add(time.Second)
	for {
		h.mu.RLock()
		link := h.links["b"]
		h.mu.RUnlock()
		if link != nil && link.ready.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("direct link did not become ready")
		}
		time.Sleep(time.Millisecond)
	}

	_, _ = peer.Write(udpPacket("10.0.0.2", "10.0.0.1", 1, 1))
	time.Sleep(20 * time.Millisecond)
	h.mu.RLock()
	still := h.links["b"] != nil
	h.mu.RUnlock()
	if !still {
		t.Fatal("direct link was torn down by a device gap")
	}
	if h.countDeviceDrop.Load() == 0 {
		t.Fatal("device-drop counter did not move")
	}

	recv := attachMeshDevice(t, h)
	_, _ = peer.Write(udpPacket("10.0.0.2", "10.0.0.1", 1, 2))
	if got := readDevicePacketWithin(recv, time.Second); len(got) == 0 {
		t.Fatal("direct link did not resume after the device returned")
	}
}

func TestMeshHubSurvivesDeviceGap(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	linkEnd, peer := newMeshPipe()
	h.SetHubLink(linkEnd)
	_ = readMeshPacket(t, peer)

	_, _ = peer.Write(udpPacket("10.0.0.9", "10.0.0.1", 1, 1))
	time.Sleep(20 * time.Millisecond)
	h.mu.RLock()
	still := h.hub != nil
	h.mu.RUnlock()
	if !still {
		t.Fatal("hub link was torn down by a device gap")
	}

	recv := attachMeshDevice(t, h)
	_, _ = peer.Write(udpPacket("10.0.0.9", "10.0.0.1", 1, 2))
	if got := readDevicePacketWithin(recv, time.Second); len(got) == 0 {
		t.Fatal("hub link did not resume after the device returned")
	}
}

func TestMeshHandleFirstFrameMarksReady(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	linkEnd.remote = "b"
	go h.Handle(context.Background(), linkEnd)
	reg := keepAliveFrame("", net.ParseIP("10.0.0.2"))
	_, _ = peer.Write(reg)
	_ = readMeshPacketWithin(peer, time.Second)

	deadline := time.Now().Add(time.Second)
	for {
		h.mu.RLock()
		link := h.links["b"]
		h.mu.RUnlock()
		if link != nil && link.ready.Load() {
			if link.bytesIn.Load() < uint64(len(reg)) {
				t.Fatalf("bytesIn = %d, want at least the first frame %d", link.bytesIn.Load(), len(reg))
			}
			if link.lastInbound.Load() == 0 {
				t.Fatal("first frame did not mark lastInbound")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("first frame did not mark the link ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMeshAddressChangeClosesLink(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, _ := meshLinkFor(t, h, "b", true)
	h.installLink(link)
	closed := make(chan MeshCloseReason, 1)
	h.SetLinkClosed(func(peer string, reason MeshCloseReason) {
		if peer == "b" {
			closed <- reason
		}
	})

	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.3"), Key: "b", Direct: true}})
	select {
	case reason := <-closed:
		if reason != MeshCloseMembership {
			t.Fatalf("close reason = %q, want membership", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("address change did not close the link")
	}
}

func TestMeshInstallAfterClose(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	h.Close()

	hubEnd, hubPeer := newMeshPipe()
	h.SetHubLink(hubEnd)
	if got := readMeshPacketWithin(hubPeer, 100*time.Millisecond); got != nil {
		t.Fatalf("SetHubLink after Close wrote %x", got)
	}
	h.mu.RLock()
	hub := h.hub
	h.mu.RUnlock()
	if hub != nil {
		t.Fatal("SetHubLink after Close installed a link")
	}

	directEnd, directPeer := newMeshPipe()
	h.AddDialedLink("b", directEnd)
	if got := readMeshPacketWithin(directPeer, 100*time.Millisecond); got != nil {
		t.Fatalf("AddDialedLink after Close wrote %x", got)
	}
	h.mu.RLock()
	_, installed := h.links["b"]
	h.mu.RUnlock()
	if installed {
		t.Fatal("AddDialedLink after Close installed a link")
	}

	handleEnd, handlePeer := newMeshPipe()
	handleEnd.remote = "b"
	_, _ = handlePeer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2")))
	if err := h.Handle(context.Background(), handleEnd); err != nil {
		t.Fatalf("Handle after Close: %v", err)
	}
	h.mu.RLock()
	_, installed = h.links["b"]
	h.mu.RUnlock()
	if installed {
		t.Fatal("Handle after Close installed a link")
	}

	devEnd, devPeer := newMeshPipe()
	if err := h.RunDevice(devEnd); !errors.Is(err, ErrTun) {
		t.Fatalf("RunDevice after Close = %v, want ErrTun", err)
	}
	if got := readMeshPacketWithin(devPeer, 100*time.Millisecond); got != nil {
		t.Fatalf("RunDevice after Close wrote %x", got)
	}
}

func TestMeshCounters(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true, Blocked: true}})
	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	c := h.MeshCounters()
	if c.Blocked == 0 {
		t.Fatalf("MeshCounters = %+v, want Blocked > 0", c)
	}
}

func TestMeshMultiAddressRegistration(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{
		{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true},
		{IP: net.ParseIP("10.0.0.3"), Key: "b", Direct: true},
	})
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	h.AddDialedLink("b", linkEnd)
	_ = readMeshPacket(t, peer) // our registration
	if _, err := peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3"))); err != nil {
		t.Fatalf("write registration: %v", err)
	}
	if got := readMeshPacketWithin(peer, time.Second); len(got) == 0 {
		t.Fatal("multi-address registration was not echoed")
	}
	if _, err := peer.Write(udpPacket("10.0.0.3", "10.0.0.1", 1, 1)); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	if got := readDevicePacketWithin(recv, time.Second); len(got) == 0 {
		t.Fatal("packet from the second member address did not reach the device")
	}
}

func TestMeshDisabledMemberIsDropped(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true, Disabled: true}})
	hubLink, hubPeer := meshTestLink(t, "hub", true)
	h.hub = hubLink

	h.dispatch(udpPacket("10.0.0.1", "10.0.0.2", 1, 1))
	expectNoMeshPacket(t, hubPeer)
	if h.countDisabled.Load() == 0 {
		t.Fatal("disabled counter did not move")
	}
}

func TestMeshDropLink(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, _ := meshLinkFor(t, h, "b", true)
	h.installLink(link)
	h.DropLink("b")
	h.mu.RLock()
	_, installed := h.links["b"]
	h.mu.RUnlock()
	if installed {
		t.Fatal("DropLink left the link installed")
	}
}

func TestMeshIPv6Dispatch(t *testing.T) {
	h := newMeshTestHandler("fd00::1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("fd00::2"), Key: "b", Direct: true}})
	link, peer := meshTestLink(t, "b", false)
	link.ready.Store(true)
	h.links["b"] = link

	h.dispatch(udp6Packet("fd00::1", "fd00::2", 1, 1))
	if got := readMeshPacket(t, peer); len(got) == 0 {
		t.Fatal("IPv6 packet did not reach the direct link")
	}
}

func TestMeshConnectingStatus(t *testing.T) {
	h := newMeshTestHandler("10.0.0.1")
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	link, _ := meshLinkFor(t, h, "b", true)
	h.installLink(link)
	for _, row := range h.MeshStatus() {
		if row.Key == "b" {
			if row.State != "connecting" {
				t.Fatalf("b state = %q, want connecting", row.State)
			}
			return
		}
	}
	t.Fatal("b row missing")
}

func TestMeshEmptyLocalIPsDropsInbound(t *testing.T) {
	h := newMeshTestHandler()
	h.SetMembers([]MeshMember{{IP: net.ParseIP("10.0.0.2"), Key: "b", Direct: true}})
	recv := attachMeshDevice(t, h)

	linkEnd, peer := newMeshPipe()
	h.AddDialedLink("b", linkEnd)
	_ = readMeshPacket(t, peer)
	_, _ = peer.Write(keepAliveFrame("", net.ParseIP("10.0.0.2")))
	_ = readMeshPacketWithin(peer, time.Second)
	_, _ = peer.Write(udpPacket("10.0.0.2", "10.0.0.1", 1, 1))
	expectNoDevicePacket(t, recv)
	if h.countForeignDst.Load() == 0 {
		t.Fatal("empty local IPs did not drop the inbound packet as foreign")
	}
}
