package tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	tun_util "github.com/go-gost/x/internal/util/tun"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

// The claim this file exists to test: a spoke cannot tell which hub it reached.
//
// A spoke is a stock tun client. It writes the same registration frame, waits
// for the same echo, uses the same passphrase and claims the same addresses
// whether its datagrams arrived on a UDP socket or on a p2p stream — nothing on
// the wire says which. So the two hubs owe the spoke the same behavior, and the
// only way that stays true is if the *same* assertions run against both: two
// separately-written suites would be allowed to drift, and a drift between them
// is exactly what a deployment against the wrong hub finds in the field.
//
// So every assertion below is written once, and run once per implementation.

// The addresses the cases are about: two spokes, one destination no spoke
// claimed, and one of the hub's own — a registration claiming that last one is
// the hub talking to itself.
var (
	compatPeerA    = net.ParseIP("10.10.0.3")
	compatPeerB    = net.ParseIP("10.10.0.4")
	compatUnrouted = net.ParseIP("10.10.0.7")
	compatHubIP    = net.ParseIP("10.10.0.9")

	compatNets = []net.IPNet{{IP: compatHubIP, Mask: net.CIDRMask(24, 32)}}

	// One auther for the whole suite, accepting every address a case registers.
	// Its allowed set matters to two cases: the self-loop guard is only reached
	// by a frame the auther would otherwise accept, and a half-authenticated
	// registration would be refused by the auther rather than by the guard.
	compatAuther = newMultiAuther("secret",
		compatPeerA.String(), compatPeerB.String(), compatHubIP.String())
)

// compatReadTimeout bounds how long a spoke waits for the hub to answer. It has
// only to outlast a datagram already in flight, so it is short — a case that
// expects silence pays it once.
const compatReadTimeout = 150 * time.Millisecond

// compatSpoke is one spoke as the hub sees it: the name its registration will be
// recorded under, and the path everything the hub sends back to it arrives on.
// The read is the whole of the client side, because from the hub's point of view
// client.go's read loop is nothing but "take the next frame from the peer".
type compatSpoke struct {
	name string
	// read returns the next frame the hub sent to this spoke, or nil when none
	// arrives within compatReadTimeout.
	read func() []byte
}

// compatHub is one implementation as the shared assertions see it. Every method
// is something a spoke can observe or provoke; no case below names a transport.
type compatHub interface {
	// spoke connects one more peer to the hub and returns it. Its registrations
	// are recorded under spoke.name.
	spoke(t *testing.T) *compatSpoke
	// register runs the registration handshake on that spoke's link: the frame
	// goes out, and the hub's answer comes back as the second result — nil when
	// the hub stayed silent, which is itself a thing a case asserts on.
	//
	// It returns once the hub has finished with the frame. A registration is
	// observable from outside only through its answer, so waiting for that
	// answer is what makes the handshake synchronous; a hub that answers nothing
	// costs one read timeout. Without the wait, every case asserting on a route
	// rather than on a reply would be racing the hub's reader goroutine.
	register(s *compatSpoke, frame []byte) (routeName string, reply []byte)
	// resolve is the destination lookup both hubs route every packet through.
	resolve(ip net.IP) (string, bool)
	// deliver puts a packet on the hub's device, as the hub's own reader would.
	deliver(pkt []byte)
	// gone ends a spoke's link, for the implementations that have such a notion.
	gone(*compatSpoke)
}

// compatCases is the shared assertion set: every case, run against every
// implementation, with an auther and without one.
func compatCases() []struct {
	name string
	run  func(t *testing.T, hub compatHub, auther auth.Authenticator)
} {
	return []struct {
		name string
		run  func(t *testing.T, hub compatHub, auther auth.Authenticator)
	}{
		// A registration with no auther registers what it claimed, and the route
		// resolves. The spoke's handshake does not depend on its keepalive
		// setting — client.go gates it on network == "udp", so it fires either
		// way — so this is the whole registration story for a deployment with no
		// auther on either hub.
		{"registers without an auther", func(t *testing.T, hub compatHub, _ auth.Authenticator) {
			name, _ := hub.register(hub.spoke(t), keepAliveFrame("secret", compatPeerA))

			if name == "" {
				t.Fatalf("the registration was recorded under an empty peer name")
			}
			if got, ok := hub.resolve(compatPeerA); !ok {
				t.Fatalf("the route for %s does not resolve after registering it", compatPeerA)
			} else if got != name {
				t.Fatalf("the route for %s resolves to %q, want the peer that registered it, %q",
					compatPeerA, got, name)
			}
		}},

		// A wrong passphrase is refused. The second half is the load-bearing one:
		// a route registered for a peer that failed to authenticate hands that
		// peer the hub's traffic.
		{"refuses a wrong passphrase", func(t *testing.T, hub compatHub, auther auth.Authenticator) {
			if auther == nil {
				t.Skip("no auther: a hub with nothing to authenticate against accepts every frame")
			}

			_, reply := hub.register(hub.spoke(t), keepAliveFrame("wrong", compatPeerA))

			// The route first: a refused registration that still registered is the
			// half that hands an unauthenticated peer the hub's traffic, and it is
			// the one a hub could get wrong while still answering correctly.
			if name, ok := hub.resolve(compatPeerA); ok {
				t.Fatalf("a refused registration left the route %q behind", name)
			}
			if reply != nil {
				t.Fatalf("a refused registration was answered with % x", reply)
			}
		}},

		// The self-loop guard: a registration claiming one of the hub's own
		// addresses would send the hub's own packets back at it.
		{"refuses the hub's own address", func(t *testing.T, hub compatHub, auther auth.Authenticator) {
			if auther == nil {
				t.Skip("no auther: the address is refused by authentication, not by the guard")
			}
			spoke := hub.spoke(t)

			_, reply := hub.register(spoke, keepAliveFrame("secret", compatHubIP))

			if name, ok := hub.resolve(compatHubIP); ok {
				t.Fatalf("a registration for the hub's own address left the route %q behind", name)
			}
			if reply != nil {
				t.Fatalf("a refused registration was answered with % x", reply)
			}

			// Proof the frame was otherwise acceptable: the same registration for a
			// peer address registers. Without it the refusal above is
			// indistinguishable from the auther's, and the guard would go untested.
			hub.register(spoke, keepAliveFrame("secret", compatPeerA))
			if _, ok := hub.resolve(compatPeerA); !ok {
				t.Fatal("the control registration did not take, so the test proves nothing")
			}
		}},

		// The property the p2p hub exists for, and the socket hub's own: a packet
		// off the device reaches the peer whose route names its destination, and
		// only that peer.
		{"delivers to the peer naming the destination", func(t *testing.T, hub compatHub, _ auth.Authenticator) {
			a, b := hub.spoke(t), hub.spoke(t)
			hub.register(a, keepAliveFrame("secret", compatPeerA))
			hub.register(b, keepAliveFrame("secret", compatPeerB))

			pkt := udpPacket(compatHubIP.String(), compatPeerA.String(), 1, 1)
			hub.deliver(pkt)

			if got := a.read(); !bytes.Equal(got, pkt) {
				t.Fatalf("the peer naming the destination got % x, want the packet % x", got, pkt)
			}
			if got := b.read(); got != nil {
				t.Fatalf("the other peer received % x, want nothing", got)
			}
		}},

		// A destination no peer claimed is a routing miss, not a delivery to
		// whichever peer spoke last.
		{"discards an unrouted destination", func(t *testing.T, hub compatHub, _ auth.Authenticator) {
			a, b := hub.spoke(t), hub.spoke(t)
			hub.register(a, keepAliveFrame("secret", compatPeerA))
			hub.register(b, keepAliveFrame("secret", compatPeerB))

			hub.deliver(udpPacket(compatHubIP.String(), compatUnrouted.String(), 1, 1))

			if got := a.read(); got != nil {
				t.Fatalf("a packet for an unrouted destination was delivered to a registered peer: % x", got)
			}
			if got := b.read(); got != nil {
				t.Fatalf("a packet for an unrouted destination was delivered to a registered peer: % x", got)
			}
		}},

		// The reply. client.go gives a spoke a read deadline of 3x its keepalive
		// period and treats any inbound byte as proof of life, so a hub that
		// registers and stays silent looks healthy until the spoke tears the
		// session down — the failure with nothing in any log to explain it, and
		// the one that would make an identical spoke config work against one hub
		// and not the other.
		{"answers the keepalive", func(t *testing.T, hub compatHub, _ auth.Authenticator) {
			spoke := hub.spoke(t)

			_, got := hub.register(spoke, keepAliveFrame("secret", compatPeerA))

			if !isKeepaliveFrame(got) {
				t.Fatalf("the registration was not answered with a keepalive frame: % x", got)
			}
			// client.go detects the echo only at exactly this length, so a hub
			// answering with any other length has answered nothing.
			if len(got) != keepAliveHeaderLength {
				t.Fatalf("the reply is %d bytes, want the %d-byte header the spoke detects",
					len(got), keepAliveHeaderLength)
			}
		}},
	}
}

// compatCase describes one implementation: how to build it, and what it asserts
// on its own account beyond the shared set. The construction is described once
// and driven by compatCases, so the duplication between the halves is
// structural — an assertion cannot drift toward one transport, because it does
// not know which transport it is running against.
type compatCase struct {
	name string
	// available reports whether the hub's delivery is constructible yet, with the
	// reason it is not when it is not. The reason is required: a skip that says
	// nothing about what is missing is indistinguishable from an omission.
	available func() (string, bool)
	new       func(t *testing.T, auther auth.Authenticator) compatHub
	// extra is the implementation's own contract, where it has one — the socket
	// hub's TTL, the p2p hub's teardown. nil where it has none.
	extra func(t *testing.T, newHub func(t *testing.T) compatHub)
}

func TestCompatHubsAgreeOnTheSpokeContract(t *testing.T) {
	for _, impl := range []compatCase{compatSocketCase(), compatP2PCase()} {
		t.Run(impl.name, func(t *testing.T) {
			if reason, ok := impl.available(); !ok {
				t.Skipf("%s hub: %s", impl.name, reason)
			}

			for _, tc := range compatCases() {
				t.Run(tc.name, func(t *testing.T) {
					for _, a := range []struct {
						name   string
						auther auth.Authenticator
					}{{"with an auther", compatAuther}, {"without an auther", nil}} {
						t.Run(a.name, func(t *testing.T) {
							tc.run(t, impl.new(t, a.auther), a.auther)
						})
					}
				})
			}

			if impl.extra != nil {
				impl.extra(t, func(t *testing.T) compatHub { return impl.new(t, compatAuther) })
			}
		})
	}
}

// ---- shared plumbing --------------------------------------------------------

// compatDevice is the hub's tun: one queue for what a test writes to it and one
// for what the hub writes back, so a packet sent to the device is never confused
// with a packet the device produced. The packet plumbing is datagramPipe's; only
// the lifetime is added here — Close unblocks the hub's reader at once, instead
// of leaving every teardown to wait out the pipe's read timeout.
type compatDevice struct {
	from *datagramPipe // the hub reads what a test sends
	to   *datagramPipe // the hub writes what a test receives

	once sync.Once
	quit chan struct{}
}

// newDevice returns the hub's device, and the two ends a test drives it with.
func newDevice() (d *compatDevice, send, recv *datagramPipe) {
	d = &compatDevice{}
	send, d.from = newDatagramPipe(16)
	d.to, recv = newDatagramPipe(16)
	d.quit = make(chan struct{})
	return d, send, recv
}

func (d *compatDevice) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.from.queue:
		return copy(p, pkt), nil
	case <-d.quit:
		return 0, io.EOF
	}
}

func (d *compatDevice) Write(p []byte) (int, error) { return d.to.Write(p) }

func (d *compatDevice) Close() error {
	d.once.Do(func() { close(d.quit) })
	return nil
}

var _ io.ReadWriter = (*compatDevice)(nil)

func compatLogger() logger.Logger {
	return xlogger.NewLogger(xlogger.LevelOption(logger.InfoLevel), xlogger.OutputOption(io.Discard))
}

// ---- the socket hub ---------------------------------------------------------

// compatSocket is the plain socket hub: a real UDP link a spoke dials, and the
// device behind it. The hub itself is server.go's own transportServer — no loop
// is reimplemented here, because a compat suite is worthless if it asserts
// against a copy of the thing rather than the thing.
type compatSocket struct {
	table *peerTable

	mu    sync.Mutex
	pc    net.PacketConn
	send  *datagramPipe
	conns []*net.UDPConn // one per spoke, in the order spoke() created them
}

func compatSocketCase() compatCase {
	const keepAlive = 20 * time.Millisecond

	return compatCase{
		name:      "socket",
		available: func() (string, bool) { return "", true },
		new: func(t *testing.T, auther auth.Authenticator) compatHub {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			dev, send, _ := newDevice()

			c := &compatSocket{pc: pc, send: send}

			// Built through Init, so the handler's table is the one a deployment
			// gets — the auther under test and the TTL parsed from config — rather
			// than a hand-built one. md.p2p stays false: this is the socket hub that
			// routes by the peer's own address, which is what findRouteFor does for
			// it.
			h := NewHandler(
				handler.AutherOption(auther),
				handler.LoggerOption(compatLogger()),
				handler.ServiceOption("tun-service"),
			).(*tunHandler)
			if err := h.Init(xmd.NewMetadata(map[string]any{
				"tun.keepalive": true,
				"tun.ttl":       keepAlive.String(),
			})); err != nil {
				t.Fatalf("init: %v", err)
			}
			c.table = h.router

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- h.transportServer(ctx, dev, pc, &tun_util.Config{Net: compatNets}, compatLogger())
			}()

			t.Cleanup(func() {
				cancel()
				pc.Close() // unblocks the link's reader
				dev.Close()
				c.mu.Lock()
				conns := c.conns
				c.mu.Unlock()
				for _, conn := range conns {
					conn.Close()
				}
				<-done // both of transportServer's readers have reported
			})

			return c
		},
		extra: func(t *testing.T, newHub func(t *testing.T) compatHub) {
			// TTL expiry is the socket hub's own contract. A p2p peer announces its
			// departure by closing its stream, so it needs no timer at all — which
			// is why this runs against one hub and not the other. Bracketed from
			// both sides: either assertion alone would let the factor drift.
			t.Run("expires a route past 3x the keepalive period", func(t *testing.T) {
				hub := newHub(t)
				hub.register(hub.spoke(t), keepAliveFrame("secret", compatPeerA))

				if name, ok := hub.resolve(compatPeerA); !ok {
					t.Fatalf("the route does not resolve at all: %q", name)
				}
				time.Sleep(2*keepAlive + keepAlive/2)
				if name, ok := hub.resolve(compatPeerA); !ok {
					t.Fatalf("the route expired at 2.5x, want it alive until 3x (got %q)", name)
				}
				time.Sleep(keepAlive + keepAlive/2)
				if name, ok := hub.resolve(compatPeerA); ok {
					t.Fatalf("the route %q survived past 3x", name)
				}
			})
		},
	}
}

func (c *compatSocket) spoke(t *testing.T) *compatSpoke {
	t.Helper()

	c.mu.Lock()
	pc := c.pc
	c.mu.Unlock()

	conn, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial the hub: %v", err)
	}

	c.mu.Lock()
	c.conns = append(c.conns, conn)
	c.mu.Unlock()

	read := func() []byte {
		_ = conn.SetReadDeadline(time.Now().Add(compatReadTimeout))
		var b [MaxMessageSize]byte
		n, err := conn.Read(b[:])
		if err != nil {
			return nil
		}
		return b[:n]
	}

	return &compatSpoke{
		// The hub records a socket peer under the address its datagrams come
		// from, which the socket only knows once it has one.
		name: conn.LocalAddr().String(),
		read: read,
	}
}

// register is a spoke's handshake on a real socket: write the frame, then read
// what the hub sends back. The read is what makes it synchronous — a hub that
// answers nothing fails the case that asked about the answer, and costs one read
// timeout in the cases that did not.
func (c *compatSocket) register(s *compatSpoke, frame []byte) (string, []byte) {
	conn := c.conn(s.name)
	if conn == nil {
		return "", nil
	}

	if _, err := conn.Write(frame); err != nil {
		return "", nil
	}
	return s.name, s.read()
}

// conn is the socket one spoke writes on, named by the address the hub knows it
// by. nil for a spoke that was never created.
func (c *compatSocket) conn(name string) *net.UDPConn {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, conn := range c.conns {
		if conn.LocalAddr().String() == name {
			return conn
		}
	}
	return nil
}

// resolve is the table's own lookup — the socket hub has one of these behind
// findRouteFor, and the p2p hub has one behind deliver.
func (c *compatSocket) resolve(ip net.IP) (string, bool) { return c.table.lookup(ip) }

func (c *compatSocket) deliver(pkt []byte) {
	c.mu.Lock()
	send := c.send
	c.mu.Unlock()

	// A blocked write would mean the hub's device reader is wedged, which the
	// assertion following this call is about to report.
	send.Write(pkt)
}

// gone does nothing: a socket peer has no link to close. It goes silent, and the
// TTL above is what reclaims it, so the socket half has no teardown to assert.
func (c *compatSocket) gone(*compatSpoke) {}

// ---- the p2p hub ------------------------------------------------------------

// compatP2PCase is the p2p half of the table.
//
// The half is a visible skip rather than an omission. What is missing is the
// server-side stream endpoint: nothing turns an inbound gRPC Tunnel stream into
// a peerStream and feeds its datagrams to p2pHub.fromSpoke, so there is no path
// by which a spoke's registration frame could reach this hub at all. Until that
// exists, "delivered to the peer naming the destination" and the rest are
// assertions against a construction rather than against the hub.
//
// The hub's own pieces are all here and tested on their own in p2p_test.go —
// dispatch, fromSpoke, peerGone — and newPeerRouter/newP2PHub are the same
// constructors this half will use. What is missing is the thing that joins them
// to a socket peer: a peer stream's inbound half, which does not exist until the
// p2p endpoint is built. So this half reports itself unavailable, and the six
// shared cases below are enumerated rather than merely absent.
func compatP2PCase() compatCase {
	return compatCase{
		name: "p2p",
		available: func() (string, bool) {
			return "no server-side stream endpoint: nothing turns an inbound gRPC Tunnel stream into a peerStream and feeds it to p2pHub.fromSpoke, so a spoke's registration frame has no path to this hub. The six shared cases and the teardown case below are pending against this hub, not absent",
				false
		},
		new: func(t *testing.T, auther auth.Authenticator) compatHub {
			// Unreachable while available() reports false, and a panic rather than
			// a stub returning a half-built hub: if the skip is ever removed
			// without this half being written, this says so at once rather than
			// passing on a construction that delivers nothing.
			panic("compatP2P: the hub is not constructible; compatP2PCase.available must be implemented first")
		},
		extra: func(t *testing.T, newHub func(t *testing.T) compatHub) {
			// The p2p half of reclamation. A stream close says a peer is gone
			// exactly; the socket hub has no such signal and guesses from silence
			// with a TTL instead — which is why this runs here and the TTL runs
			// there, and why neither is asserted against the other.
			t.Run("a stream close reclaims only that peer's routes", func(t *testing.T) {
				hub := newHub(t)
				closing := hub.spoke(t)
				hub.register(closing, keepAliveFrame("secret", compatPeerA))
				hub.register(hub.spoke(t), keepAliveFrame("secret", compatPeerB))

				hub.gone(closing)

				if name, ok := hub.resolve(compatPeerA); ok {
					t.Fatalf("the closed peer's route %q survived its stream", name)
				}
				if name, ok := hub.resolve(compatPeerB); !ok || name == "" {
					t.Fatalf("the other peer's route = %q, %v, want it untouched", name, ok)
				}
			})
		},
	}
}
