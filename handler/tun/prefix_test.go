package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestPrefixLookupLongestPrefixAndAllow(t *testing.T) {
	pt := newPeerTable(nil, 0, "tun-service", nil)
	pt.SetPrefixRoutes(map[netip.Prefix]prefixRoute{
		netip.MustParsePrefix("192.168.0.0/16"):  {Peer: "peerWide"},
		netip.MustParsePrefix("192.168.50.0/24"): {Peer: "peerB"},
	})
	// Longest match wins.
	if peer, _ := pt.lookupPrefix(net.ParseIP("192.168.50.9"), "peerA"); peer != "peerB" {
		t.Fatalf("dst in the /24 resolved to %q, want peerB", peer)
	}
	if peer, _ := pt.lookupPrefix(net.ParseIP("192.168.77.9"), "peerA"); peer != "peerWide" {
		t.Fatalf("dst outside the /24 resolved to %q, want peerWide", peer)
	}
	// A member's exact route still outranks any prefix.
	pt.set(net.ParseIP("10.10.100.5"), "peerA")
	if peer, _ := pt.lookupPrefix(net.ParseIP("10.10.100.5"), "peerA"); peer != "peerA" {
		t.Fatal("an exact route must outrank a prefix")
	}
	// An allow list gates use.
	pt.SetPrefixRoutes(map[netip.Prefix]prefixRoute{
		netip.MustParsePrefix("192.168.50.0/24"): {Peer: "peerB", Allow: []string{"peerA"}},
	})
	if _, ok := pt.lookupPrefix(net.ParseIP("192.168.50.9"), "peerZ"); ok {
		t.Fatal("a peer outside allow must not use the route")
	}
}

func TestDispatchFallsThroughExactThenPrefixThenNoRoute(t *testing.T) {
	// One destination in a claimed LAN is delivered by prefix: the table has
	// no exact route for it, the prefix table names the LAN's owner, and the
	// packet reaches that peer's stream and no other. The source is owned by
	// no member — this is hub-local traffic, which has no member key — and
	// the route is unrestricted, so this case also pins the no-requester
	// edge: no allow list is drawn, so the hub's own traffic crosses.
	_, peerLanEnd := newDatagramPipe(4)
	_, peerOtherEnd := newDatagramPipe(4)

	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-lan", peerLanEnd))
	router.install(newPeerStream(context.Background(), "peer-other", peerOtherEnd))
	router.table.SetPrefixRoutes(map[netip.Prefix]prefixRoute{
		netip.MustParsePrefix("192.168.50.0/24"): {Peer: "peer-lan"},
	})

	hub := newP2PHub(nopDevice{}, router, nil, nil)
	pkt := udpPacket("10.10.0.9", "192.168.50.9", 1, 1)
	hub.dispatch(pkt)

	var got [MaxMessageSize]byte
	n, err := peerLanEnd.Read(got[:])
	if err != nil {
		t.Fatalf("peer-lan read: %v", err)
	}
	if !bytes.Equal(got[:n], pkt) {
		t.Fatalf("peer-lan got % x, want % x", got[:n], pkt)
	}
	select {
	case pkt := <-peerOtherEnd.queue:
		t.Fatalf("peer-other received % x, want nothing", pkt)
	default:
	}

	// The same destination with an empty prefix table still takes the
	// existing ErrNoRoute path — the fall-through added a case, not a new
	// outcome.
	router.table.SetPrefixRoutes(nil)
	err = router.deliverFrom(net.ParseIP("192.168.50.9"), udpPacket("10.10.0.9", "192.168.50.9", 1, 2), "")
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("deliverFrom = %v, want ErrNoRoute with no prefix table", err)
	}
}

// A restricted LAN route admits its allow list and no one else, and for
// hub-local traffic — the only traffic dispatch sees, every remote peer
// entering through fromSpoke's authenticated gate — the requester is
// resolved from the source address, best-effort: the hub's own host is the
// only stack that can originate here, and no member key vouches for it. A
// source owned by a member inside the list is delivered; one owned by a
// member outside it is denied; a source no member owns has no requester to
// vouch for it, so it is denied too. The denials are unrouted events in the
// existing accounting, not a new failure path.
func TestDispatchHubLocalRequesterResolvedFromSource(t *testing.T) {
	_, peerLanEnd := newDatagramPipe(4)

	var mu sync.Mutex
	var warnings []string
	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-lan", peerLanEnd))
	// The requester resolution keys on the source address: a hub-host
	// process using a member's tun address resolves to that member. One
	// member sits inside the route's allow list, one outside it.
	router.table.set(net.ParseIP("10.10.0.3"), "peer-in")
	router.table.set(net.ParseIP("10.10.0.4"), "peer-out")
	router.table.SetPrefixRoutes(map[netip.Prefix]prefixRoute{
		netip.MustParsePrefix("192.168.50.0/24"): {Peer: "peer-lan", Allow: []string{"peer-in"}},
	})

	// A hub per case, not one shared: a denial is counted per unrouted
	// window, so the second denial on one hub would be within the first's
	// window and warn nothing — each case needs its own tally to see its
	// own warning.
	newHub := func() *p2pHub {
		mu.Lock()
		warnings = nil
		mu.Unlock()
		return newP2PHub(nopDevice{}, router, nil, func(msg string) {
			mu.Lock()
			warnings = append(warnings, msg)
			mu.Unlock()
		})
	}

	// A source owned by a member inside the allow list is delivered.
	hub := newHub()
	in := udpPacket("10.10.0.3", "192.168.50.9", 1, 1)
	hub.dispatch(in)
	var got [MaxMessageSize]byte
	n, err := peerLanEnd.Read(got[:])
	if err != nil {
		t.Fatalf("peer-lan read: %v", err)
	}
	if !bytes.Equal(got[:n], in) {
		t.Fatalf("peer-lan got % x, want % x", got[:n], in)
	}

	// A source owned by a member outside the allow list is denied: no
	// delivery, and the denial is the existing unrouted accounting.
	hub = newHub()
	hub.dispatch(udpPacket("10.10.0.4", "192.168.50.9", 2, 1))
	select {
	case pkt := <-peerLanEnd.queue:
		t.Fatalf("a member outside allow was delivered % x", pkt)
	default:
	}
	mu.Lock()
	w := append([]string(nil), warnings...)
	mu.Unlock()
	if len(w) != 1 || !strings.Contains(w[0], "no route for 192.168.50.9") {
		t.Fatalf("warnings = %v, want one unrouted warning for the denied member", w)
	}

	// A source no member owns is denied the same way: no requester means no
	// one to admit, and a restricted route must never treat that as a pass.
	hub = newHub()
	hub.dispatch(udpPacket("10.10.0.99", "192.168.50.9", 3, 1))
	select {
	case pkt := <-peerLanEnd.queue:
		t.Fatalf("an unowned source was delivered % x", pkt)
	default:
	}
	mu.Lock()
	w = append([]string(nil), warnings...)
	mu.Unlock()
	if len(w) != 1 || !strings.Contains(w[0], "no route for 192.168.50.9") {
		t.Fatalf("warnings = %v, want one unrouted warning for the unowned source", w)
	}
}

// The allow gate keys off the authenticated stream peer, not the packet's
// self-declared source field: a packet arriving on a spoke's stream whose
// source claims an allow-listed member's address is denied when the spoke it
// arrived from is outside the route's allow list. Dropped before the device,
// too — sent on instead, it would come back through dispatch, whose requester
// is the source field's owner, and the claimed source would vouch for it.
func TestFromSpokeAllowGatesOnAuthenticatedPeer(t *testing.T) {
	device := newWriteRecorder(MaxMessageSize)
	_, peerLanEnd := newDatagramPipe(4)
	_, outEnd := newDatagramPipe(4)
	_, inEnd := newDatagramPipe(4)

	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-lan", peerLanEnd))
	out := newPeerStream(context.Background(), "peer-out", outEnd)
	in := newPeerStream(context.Background(), "peer-in", inEnd)
	router.install(out)
	router.install(in)
	// The route is restricted to peer-in, and the packets below all claim
	// peer-in's tun address as their source: only the stream a packet
	// arrives on tells the two members apart.
	router.table.set(net.ParseIP("10.10.0.3"), "peer-in")
	router.table.SetPrefixRoutes(map[netip.Prefix]prefixRoute{
		netip.MustParsePrefix("192.168.50.0/24"): {Peer: "peer-lan", Allow: []string{"peer-in"}},
	})

	var mu sync.Mutex
	var warnings []string
	hub := newP2PHub(device, router, nil, func(msg string) {
		mu.Lock()
		warnings = append(warnings, msg)
		mu.Unlock()
	})

	// A spoofed source does not cross the gate: the destination matches the
	// route, the route admits peer-in, and the source claims peer-in's
	// address — but the packet arrives on peer-out's stream, so it is denied:
	// not delivered, not written to the device, and counted as unrouted.
	pkt := udpPacket("10.10.0.3", "192.168.50.9", 1, 1)
	if err := hub.fromSpoke(out, pkt); err != nil {
		t.Fatalf("fromSpoke(spoofed source): %v", err)
	}
	select {
	case pkt := <-peerLanEnd.queue:
		t.Fatalf("a spoofed source crossed the allow gate: % x", pkt)
	default:
	}
	if got := device.received(); len(got) != 0 {
		t.Fatalf("a denied packet was written to the device: % x", got)
	}
	mu.Lock()
	w := append([]string(nil), warnings...)
	mu.Unlock()
	if len(w) != 1 || !strings.Contains(w[0], "no route for 192.168.50.9") {
		t.Fatalf("warnings = %v, want one unrouted warning for the denied spoke", w)
	}

	// The authenticated peer crosses: the same claimed source, arriving on
	// peer-in's own stream, is delivered by prefix — and directly, not
	// through the device.
	pkt = udpPacket("10.10.0.3", "192.168.50.9", 2, 1)
	if err := hub.fromSpoke(in, pkt); err != nil {
		t.Fatalf("fromSpoke(allowed): %v", err)
	}
	var got [MaxMessageSize]byte
	n, err := peerLanEnd.Read(got[:])
	if err != nil {
		t.Fatalf("peer-lan read: %v", err)
	}
	if !bytes.Equal(got[:n], pkt) {
		t.Fatalf("peer-lan got % x, want % x", got[:n], pkt)
	}
	if got := device.received(); len(got) != 0 {
		t.Fatalf("an allowed packet took the device: % x", got)
	}
}
