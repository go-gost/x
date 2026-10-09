package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
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
	// packet reaches that peer's stream and no other.
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
