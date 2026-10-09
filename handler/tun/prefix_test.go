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
	// packet reaches that peer's stream and no other. The source is owned
	// by no member and the route is unrestricted, so this case also pins the
	// no-requester edge: a LAN host is not a member, and an empty allow list
	// must admit it or the LAN-to-LAN traffic the route exists for never
	// moves.
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

// A restricted LAN route admits its allow list and no one else, and the
// requester it gates is resolved per packet from the source address: the
// member that owns the source is the member asking. A member inside the
// list is delivered; a member outside it is denied; a source no member owns
// has no requester to vouch for it, so it is denied too. The denials are
// unrouted events in the existing accounting, not a new failure path.
func TestDispatchAllowGatesBySourceOwner(t *testing.T) {
	_, peerLanEnd := newDatagramPipe(4)

	var mu sync.Mutex
	var warnings []string
	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-lan", peerLanEnd))
	// The requesting members, one inside the route's allow list and one
	// outside it. Their tun addresses are what the requester resolution keys
	// on — the peer keys travel in no packet.
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

	// A member inside the allow list is delivered.
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

	// A member outside the allow list is denied: no delivery, and the denial
	// is the existing unrouted accounting.
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
