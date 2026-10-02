package tun

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
)

// keepAliveFrame builds the registration frame the tun client sends: a 4-byte
// magic header, the passphrase zero-padded to 16 bytes, then each claimed
// address as 16 bytes (see client.go's keepalive).
func keepAliveFrame(passphrase string, ips ...net.IP) []byte {
	b := make([]byte, keepAliveHeaderLength+len(ips)*net.IPv6len)
	copy(b[:4], magicHeader)
	copy(b[4:keepAliveHeaderLength], passphrase)
	pos := keepAliveHeaderLength
	for _, ip := range ips {
		copy(b[pos:pos+net.IPv6len], ip.To16())
		pos += net.IPv6len
	}
	return b
}

// testAuther accepts one passphrase for one address, which is all the
// registration path authenticates.
type testAuther struct {
	user, passphrase string
}

func (a *testAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if user != a.user {
		return "", false
	}
	return user, password == a.passphrase
}

func newTestAuther(passphrase string) auth.Authenticator {
	return &testAuther{user: "10.10.0.3", passphrase: passphrase}
}

// multiAuther accepts a passphrase for a set of addresses. testAuther covers one
// address; a real tun config registers every address in config.Net at once, so
// a registration that authenticates some addresses and not others is the case
// that matters and needs an auther that can express it.
type multiAuther struct {
	allowed    map[string]bool
	passphrase string
}

func newMultiAuther(passphrase string, allowed ...string) auth.Authenticator {
	set := make(map[string]bool, len(allowed))
	for _, ip := range allowed {
		set[ip] = true
	}
	return &multiAuther{allowed: set, passphrase: passphrase}
}

func (a *multiAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if password != a.passphrase || !a.allowed[user] {
		return "", false
	}
	return user, true
}

// recordingAuther captures the auth.Options each Authenticate call received.
// A plugin auther puts Service on the wire to an external process, so a missing
// service name is not a cosmetic difference — it changes the request the
// external auther sees, and no other test here can detect it.
type recordingAuther struct {
	user, passphrase string

	mu       sync.Mutex
	services []string
}

func (a *recordingAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	var options auth.Options
	for _, opt := range opts {
		opt(&options)
	}
	a.mu.Lock()
	a.services = append(a.services, options.Service)
	a.mu.Unlock()
	if user != a.user {
		return "", false
	}
	return user, password == a.passphrase
}

// seenServices returns the service name each recorded call received.
func (a *recordingAuther) seenServices() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.services...)
}

func TestTransportRouterAuthenticatesWithService(t *testing.T) {
	a := &recordingAuther{user: "10.10.0.3", passphrase: "secret"}
	pt := newPeerTable(a, 0, "tun-service", nil)

	if _, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", net.ParseIP("10.10.0.3")), "peer-a", nil); !ok {
		t.Fatal("onKeepalive refused a valid frame")
	}

	got := a.seenServices()
	if len(got) != 1 {
		t.Fatalf("authenticate called %d times, want 1: %v", len(got), got)
	}
	if got[0] != "tun-service" {
		t.Fatalf("auth.Options.Service = %q, want %q", got[0], "tun-service")
	}
}

// An empty service is a real configuration (a handler registered without one),
// so it must authenticate normally rather than being rejected or panicking.
func TestTransportRouterAuthenticatesWithoutService(t *testing.T) {
	a := &recordingAuther{user: "10.10.0.3", passphrase: "secret"}
	pt := newPeerTable(a, 0, "", nil)

	ips, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", net.ParseIP("10.10.0.3")), "peer-a", nil)
	if !ok {
		t.Fatal("onKeepalive refused a valid frame with no service configured")
	}
	if len(ips) != 1 {
		t.Fatalf("peer IPs = %v, want one", ips)
	}
	if got := a.seenServices(); len(got) != 1 || got[0] != "" {
		t.Fatalf("auth.Options.Service = %v, want one empty string", got)
	}
}

// A table with no auther registers without authenticating at all — the
// unauthenticated deployment. Nothing panics and the route still appears.
func TestTransportRouterNoAuther(t *testing.T) {
	pt := newPeerTable(nil, 0, "tun-service", nil)

	if _, ok := pt.onKeepalive(context.Background(), keepAliveFrame("", net.ParseIP("10.10.0.3")), "peer-a", nil); !ok {
		t.Fatal("onKeepalive refused a valid frame with no auther")
	}
	if name, ok := pt.lookup(net.ParseIP("10.10.0.3")); !ok || name != "peer-a" {
		t.Fatalf("lookup = %q, %v, want \"peer-a\", true", name, ok)
	}
}

func TestTransportRouterRegistersKeepalive(t *testing.T) {
	pt := newPeerTable(newTestAuther("secret"), 0, "tun-service", nil)

	ips, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", net.ParseIP("10.10.0.3")), "peer-a", nil)
	if !ok {
		t.Fatal("onKeepalive refused a valid frame")
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.10.0.3")) {
		t.Fatalf("peer IPs = %v, want [10.10.0.3]", ips)
	}

	name, ok := pt.lookup(net.ParseIP("10.10.0.3"))
	if !ok || name != "peer-a" {
		t.Fatalf("lookup = %q, %v, want \"peer-a\", true", name, ok)
	}
}

func TestTransportRouterRejectsUnauthenticated(t *testing.T) {
	pt := newPeerTable(newTestAuther("secret"), 0, "tun-service", nil)

	_, ok := pt.onKeepalive(context.Background(), keepAliveFrame("wrong", net.ParseIP("10.10.0.3")), "peer-a", nil)
	if ok {
		t.Fatal("onKeepalive accepted a wrong passphrase")
	}
	if _, ok := pt.lookup(net.ParseIP("10.10.0.3")); ok {
		t.Fatal("a refused keepalive left a route behind")
	}
}

// TestTransportRouterExpiresByTTL brackets the expiry window from both sides:
// the route must still resolve past 2x the keepalive period, and be gone past
// 3x. Either assertion alone would let the factor drift — only the pair pins it,
// which is why a shorter window must survive and a longer one must not.
func TestTransportRouterExpiresByTTL(t *testing.T) {
	const ttl = 20 * time.Millisecond
	ip := net.ParseIP("10.10.0.3")

	register := func() *peerTable {
		pt := newPeerTable(newTestAuther("secret"), ttl, "tun-service", nil)
		if _, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", ip), "peer-a", nil); !ok {
			t.Fatal("onKeepalive refused a valid frame")
		}
		return pt
	}

	t.Run("present inside the window", func(t *testing.T) {
		pt := register()
		time.Sleep(2*ttl + ttl/2)
		if name, ok := pt.lookup(ip); !ok {
			t.Fatalf("route expired at 2.5x ttl, want it alive until 3x (got %q)", name)
		} else if name != "peer-a" {
			t.Fatalf("lookup = %q, want %q", name, "peer-a")
		}
	})

	t.Run("expired past the window", func(t *testing.T) {
		pt := register()
		time.Sleep(3*ttl + ttl/2)
		if name, ok := pt.lookup(ip); ok {
			t.Fatalf("route %q survived past 3x ttl", name)
		}
	})
}

// A registration claiming one of the hub's own networks is the hub talking to
// itself: the route would loop its own packets back at it. It must be refused
// outright, leaving no route behind.
//
// The auther accepts this address on purpose. If it did not, the frame would be
// refused by authentication instead and the guard would go untested — a test
// that passes for the wrong reason is worse than no test.
func TestTransportRouterRejectsOwnNetwork(t *testing.T) {
	own := net.ParseIP("10.10.0.9")
	auther := &testAuther{user: own.String(), passphrase: "secret"}
	pt := newPeerTable(auther, 0, "tun-service", nil)

	ownNets := []net.IPNet{{IP: own, Mask: net.CIDRMask(24, 32)}}
	ips, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", own), "peer-a", ownNets)
	if ok {
		t.Fatalf("onKeepalive accepted a registration for the hub's own network, peer IPs = %v", ips)
	}
	if ips != nil {
		t.Fatalf("refused registration still returned peer IPs: %v", ips)
	}
	if name, ok := pt.lookup(own); ok {
		t.Fatalf("a refused registration left the route %q behind", name)
	}

	// Proof the frame was otherwise acceptable: the same registration against
	// the same auther, with no ownNets to match, registers. Without this, the
	// two refusals above are indistinguishable.
	if _, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", own), "peer-a", nil); !ok {
		t.Fatal("the same frame was refused even without ownNets: the test proves nothing")
	}
	if name, ok := pt.lookup(own); !ok || name != "peer-a" {
		t.Fatalf("control registration did not take: lookup = %q, %v", name, ok)
	}
}

// The parsing refusals: a frame that is not a registration at all, or whose
// address payload is not a whole number of 16-byte addresses, must be refused
// without registering anything. Task 2 routes every inbound datagram through
// this parse, so a silent acceptance here would register a route from a
// malformed frame.
func TestTransportRouterRejectsMalformedFrame(t *testing.T) {
	ip := net.ParseIP("10.10.0.3")

	// A bare 20-byte keepalive echo carries no addresses, so it is not a
	// registration: the server side must treat it as a packet, not a route.
	noAddresses := append([]byte(nil), magicHeader...)
	noAddresses = append(noAddresses, make([]byte, keepAliveHeaderLength-len(magicHeader))...)

	wrongMagic := keepAliveFrame("secret", ip)
	copy(wrongMagic[:4], "XXXX")

	shortPayload := keepAliveFrame("secret", ip)[:keepAliveHeaderLength+3]

	tests := []struct {
		name  string
		frame []byte
	}{
		{"no addresses", noAddresses},
		{"wrong magic", wrongMagic},
		{"payload not a multiple of 16", shortPayload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := newPeerTable(newTestAuther("secret"), 0, "tun-service", nil)

			if ips, ok := pt.onKeepalive(context.Background(), tt.frame, "peer-a", nil); ok {
				t.Fatalf("onKeepalive accepted a malformed frame, peer IPs = %v", ips)
			}
			if name, ok := pt.lookup(ip); ok {
				t.Fatalf("a malformed frame left the route %q behind", name)
			}
		})
	}
}

// A real tun config puts every address in config.Net into one registration, so
// a multi-address frame is the common case. The passphrase covers the whole
// frame: one bad address must sink the entire registration, because a frame
// whose first address authenticates and whose second does not is exactly the
// half-trusted registration the auther loop is written to prevent.
func TestTransportRouterMultiAddressRegistration(t *testing.T) {
	first := net.ParseIP("10.10.0.3")
	second := net.ParseIP("10.10.0.4")

	t.Run("all authenticate", func(t *testing.T) {
		pt := newPeerTable(newMultiAuther("secret", first.String(), second.String()), 0, "tun-service", nil)

		ips, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", first, second), "peer-a", nil)
		if !ok {
			t.Fatal("onKeepalive refused a frame whose addresses all authenticate")
		}
		if len(ips) != 2 {
			t.Fatalf("peer IPs = %v, want two addresses", ips)
		}
		for _, ip := range []net.IP{first, second} {
			if name, ok := pt.lookup(ip); !ok || name != "peer-a" {
				t.Fatalf("lookup(%s) = %q, %v, want \"peer-a\", true", ip, name, ok)
			}
		}
	})

	t.Run("second refused sinks the whole registration", func(t *testing.T) {
		// The auther accepts only the first address.
		pt := newPeerTable(newMultiAuther("secret", first.String()), 0, "tun-service", nil)

		ips, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", first, second), "peer-a", nil)
		if ok {
			t.Fatalf("onKeepalive accepted a half-authenticated frame, peer IPs = %v", ips)
		}
		if ips != nil {
			t.Fatalf("refused registration still returned peer IPs: %v", ips)
		}
		// The address that did authenticate must not have been registered on
		// its own: a partial registration is the failure mode, not a partial
		// success.
		if name, ok := pt.lookup(first); ok {
			t.Fatalf("the authenticated address was registered anyway, as %q", name)
		}
		if name, ok := pt.lookup(second); ok {
			t.Fatalf("the refused address was registered as %q", name)
		}
	})
}

// A peer's keepalives must keep its route alive, and a peer re-registering an
// address it already owns must take it over. Both go through set's refresh
// branch, which is what keeps a healthy peer from being expired.
func TestTransportRouterSetRefreshesExistingRoute(t *testing.T) {
	ip := net.ParseIP("10.10.0.3")
	pt := newPeerTable(newTestAuther("secret"), 0, "tun-service", nil)

	pt.set(ip, "peer-a")
	if name, ok := pt.lookup(ip); !ok || name != "peer-a" {
		t.Fatalf("lookup after first set = %q, %v, want \"peer-a\", true", name, ok)
	}

	// Same peer, same address: the route is refreshed in place and still
	// resolves to it. This is the keepalive loop's steady state.
	pt.set(ip, "peer-a")
	if name, ok := pt.lookup(ip); !ok || name != "peer-a" {
		t.Fatalf("lookup after same-name refresh = %q, %v, want \"peer-a\", true", name, ok)
	}

	// A different peer claiming the same address takes it over.
	pt.set(ip, "peer-b")
	if name, ok := pt.lookup(ip); !ok || name != "peer-b" {
		t.Fatalf("lookup after takeover = %q, %v, want \"peer-b\", true", name, ok)
	}

	// And the reverse index followed the takeover, so dropPeer still works.
	pt.dropPeer("peer-a")
	if name, ok := pt.lookup(ip); !ok || name != "peer-b" {
		t.Fatalf("dropPeer(peer-a) disturbed peer-b's route: lookup = %q, %v", name, ok)
	}
	pt.dropPeer("peer-b")
	if _, ok := pt.lookup(ip); ok {
		t.Fatal("dropPeer(peer-b) left the route behind")
	}
}

func TestTransportRouterDropsPeerRoutes(t *testing.T) {
	pt := newPeerTable(newTestAuther("secret"), 0, "tun-service", nil)

	a := net.ParseIP("10.10.0.3")
	if _, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", a), "peer-a", nil); !ok {
		t.Fatal("onKeepalive refused peer-a")
	}
	// peer-b is registered directly: the auther above only knows one address,
	// and this test is about which routes dropPeer takes, not about the
	// registration handshake.
	b := net.ParseIP("10.10.0.4")
	pt.set(b, "peer-b")

	pt.dropPeer("peer-a")

	if _, ok := pt.lookup(a); ok {
		t.Fatal("dropPeer left peer-a's route behind")
	}
	if name, ok := pt.lookup(b); !ok || name != "peer-b" {
		t.Fatalf("lookup after dropPeer = %q, %v, want \"peer-b\", true", name, ok)
	}
}

func TestTransportRouterUnknownDestination(t *testing.T) {
	pt := newPeerTable(newTestAuther("secret"), 0, "tun-service", nil)

	if _, ok := pt.onKeepalive(context.Background(), keepAliveFrame("secret", net.ParseIP("10.10.0.3")), "peer-a", nil); !ok {
		t.Fatal("onKeepalive refused a valid frame")
	}
	if name, ok := pt.lookup(net.ParseIP("10.10.0.9")); ok {
		t.Fatalf("unregistered destination resolved to %q", name)
	}
}
