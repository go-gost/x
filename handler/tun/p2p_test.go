package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	ictx "github.com/go-gost/x/internal/ctx"
	tun_util "github.com/go-gost/x/internal/util/tun"
	xmd "github.com/go-gost/x/metadata"
)

// datagramPipe is a unidirectional pipe whose boundaries survive: every Write on
// one end reaches the reader on the other as exactly one Read, never a fragment
// or a merge.
//
// A plain net.Pipe is a byte stream, so a test on one can pass on a torn
// packet — the halves of an interleaved write read back as one plausible-looking
// buffer. That is precisely what the concurrency tests below exist to catch, so
// the harness they run on has to preserve the boundaries a tun device preserves.
//
// The queue is bounded and a write blocks when it is full, which is what a
// device's own buffer does.
type datagramPipe struct {
	queue chan []byte

	closeOnce sync.Once
}

func newDatagramPipe(depth int) (tx, rx *datagramPipe) {
	tx = &datagramPipe{queue: make(chan []byte, depth)}
	rx = &datagramPipe{queue: tx.queue}
	return
}

func (p *datagramPipe) Write(b []byte) (int, error) {
	// Copy: the caller owns b and may reuse it the moment Write returns, and the
	// reader may not have picked this message up yet.
	pkt := make([]byte, len(b))
	copy(pkt, b)

	select {
	case p.queue <- pkt:
		return len(b), nil
	case <-time.After(2 * time.Second):
		return 0, errors.New("datagramPipe: write timed out")
	}
}

func (p *datagramPipe) Read(b []byte) (int, error) {
	select {
	case pkt := <-p.queue:
		return copy(b, pkt), nil
	case <-time.After(2 * time.Second):
		return 0, errors.New("datagramPipe: read timed out")
	}
}

// Close is how a test ends a run() reader that is parked in Read.
func (p *datagramPipe) Close() error {
	p.closeOnce.Do(func() { close(p.queue) })
	return nil
}

// writeRecorder stands in for the tun device's write side, and it copies through
// one shared buffer the way tunDevice does (listener/tun/tun.go assigns d.wbufs[0]
// and copies through d.wbuf with no lock).
//
// That shared buffer is the whole point. Every Write copies p into it in two
// halves with a gap in between, so if two writers are ever inside Write together
// the halves splice and the recorded packet is neither one's. With the hub's
// write lock in place that cannot happen; remove the lock and this reports both
// a data race on the buffer and a spliced packet.
//
// The gap only widens a window that already exists — a device write is a syscall
// with the buffer pinned for its duration, so the exposure is the overlap, not
// the sleep.
type writeRecorder struct {
	mu    sync.Mutex
	scrub []byte // the device's one write buffer
	// entered is set for the duration of a write, so an overlap is recorded even
	// when the two spliced packets happen to reassemble correctly.
	entered  bool
	overlaps int
	packets  [][]byte
}

func newWriteRecorder(size int) *writeRecorder {
	return &writeRecorder{scrub: make([]byte, size)}
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	// Already inside a write: two writers sharing the buffer at once.
	if w.entered {
		w.overlaps++
	}
	w.entered = true
	w.mu.Unlock()

	half := len(p) / 2
	copy(w.scrub[:half], p[:half])
	time.Sleep(20 * time.Microsecond)
	copy(w.scrub[half:len(p)], p[half:])

	w.mu.Lock()
	w.entered = false
	cp := make([]byte, len(p))
	copy(cp, w.scrub[:len(p)]) // the buffer as the kernel would have seen it
	w.packets = append(w.packets, cp)
	w.mu.Unlock()

	return len(p), nil
}

// Read is never called on a recorder: the hub's reader is exercised by
// TestP2PRunDispatchesUntilDeviceCloses, which reads from a pipe. It exists so a
// recorder can stand in as the device wherever the hub takes an io.ReadWriter.
func (w *writeRecorder) Read([]byte) (int, error) {
	return 0, errors.New("writeRecorder: read")
}

func (w *writeRecorder) received() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.packets...)
}

func (w *writeRecorder) overlapping() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.overlaps
}

// streamRecorder models what a p2p datagram conn really is: a byte stream that
// each Write frames as [2-byte big-endian length][payload], exactly as
// p2p/internal/host/frame.go and x/p2p/streamconn do.
//
// It has to model the stream, not the message. A datagram-shaped pipe delivers
// each Write through a channel, which is atomic per message — so it cannot splice
// two writers, and a test on one passes with peerStream's write lock removed
// (verified). The corruption exists *inside* the byte stream: two concurrent
// writes put one frame's length prefix against the other's payload, and the
// reader then takes every frame length from the wrong offset. Only a byte stream
// can produce that.
//
// Write takes no lock, on purpose: it is the stream, and a real one is
// unsynchronized. Locking it here would test the recorder rather than the hub.
type streamRecorder struct {
	raw []byte // the peer's byte stream, accumulated
}

func (r *streamRecorder) Write(p []byte) (int, error) {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))

	// Two appends with a gap, as appendFrame writes header then body: a second
	// writer landing here interleaves the two. The gap only widens a window the
	// unsynchronized appends already leave open; it is kept small because it is
	// paid on every write of every round.
	r.raw = append(r.raw, hdr[:]...)
	time.Sleep(2 * time.Microsecond)
	r.raw = append(r.raw, p...)
	return len(p), nil
}

// Close satisfies io.WriteCloser; frames() is read after the writers join.
func (r *streamRecorder) Close() error { return nil }

// frames parses the accumulated stream the way the peer's conn would. A spliced
// stream yields frames that are not among the sent ones, so the caller compares
// each frame against what it sent. Called only after the writers have joined.
func (r *streamRecorder) frames() ([][]byte, error) {
	var out [][]byte
	raw := r.raw
	for len(raw) >= 2 {
		n := int(binary.BigEndian.Uint16(raw[:2]))
		if len(raw) < 2+n {
			return out, fmt.Errorf("stream ends mid-frame: %d bytes left for a %d-byte payload", len(raw)-2, n)
		}
		out = append(out, append([]byte(nil), raw[2:2+n]...))
		raw = raw[2+n:]
	}
	return out, nil
}

// discard is a stream that accepts writes and counts closes, for the tests that
// exercise neither delivery direction.
type discard struct {
	closes *int
}

func (d discard) Write(p []byte) (int, error) { return len(p), nil }

func (d discard) Close() error {
	*d.closes++
	return nil
}

// nopDevice is a device that is written to but never read, for the tests that
// only exercise delivery into the device.
type nopDevice struct{}

func (nopDevice) Read([]byte) (int, error) { return 0, errors.New("nopDevice: read") }

func (nopDevice) Write([]byte) (int, error) { return 0, nil }

// Every generated packet ends in packetTag(tag): a fixed-width tail that names
// the packet's sender and sequence number, zero-padded.
//
// The width is fixed for two reasons. A test recovers the tag by slicing the last
// packetTagLen bytes rather than scanning — scanning would mistake a spliced
// packet's halves for a tag that happens to be present, which is exactly the
// corruption these tests hunt. And the padding is what makes that slice exact: an
// unpadded tag would end wherever the string happened to end, so a longer tag
// would silently truncate into a different tag (which is how a whole tag format
// collided with itself during development).
const (
	packetTagLen = 20
	// tags are "spoke=<spoke> seq=<seq>", both numbers, so their lengths vary;
	// the padding is what pins the tail's position.
	packetTagPad = " "
)

func packetTag(spoke, seq int) string {
	t := fmt.Sprintf("spoke=%d seq=%d", spoke, seq)
	if len(t) >= packetTagLen {
		panic("packetTag: tag longer than packetTagLen; widen it")
	}
	return t + strings.Repeat(packetTagPad, packetTagLen-len(t))
}

// tagOf recovers the tag packetTag wrote. ok is false when these bytes are not a
// packet any test generated — a spliced write, most likely.
func tagOf(pkt []byte) (spoke, seq int, ok bool) {
	if len(pkt) < packetTagLen {
		return 0, 0, false
	}
	tail := strings.TrimRight(string(pkt[len(pkt)-packetTagLen:]), packetTagPad)
	if !strings.HasPrefix(tail, "spoke=") {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(tail, "spoke=%d seq=%d", &spoke, &seq); err != nil {
		return 0, 0, false
	}
	return spoke, seq, true
}

// packetKey is the map key for one generated packet, matching what tagOf
// recovers from the bytes.
func packetKey(spoke, seq int) string {
	return fmt.Sprintf("spoke=%d seq=%d", spoke, seq)
}

// udpPacket builds a minimal IPv4 UDP packet between the endpoints, ending in
// packetTag(tag).
func udpPacket(src, dst string, spoke, seq int) []byte {
	payload := []byte(packetTag(spoke, seq))
	b := make([]byte, 20+8+len(payload))
	b[0] = 4<<4 | 5 // IPv4, 5 words of header
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64 // TTL
	b[9] = 17 // UDP
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(b[20:22], uint16(8+len(payload))) // UDP length
	copy(b[28:], payload)                                        // after the 20-byte IPv4 + 8-byte UDP headers
	return b
}

// udp6Packet is udpPacket for IPv6, which destinationOf handles on its other
// branch and which therefore needs a case of its own.
func udp6Packet(src, dst string, spoke, seq int) []byte {
	payload := []byte(packetTag(spoke, seq))
	b := make([]byte, 40+8+len(payload))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40)) // payload length
	b[6] = 17                                             // next header: UDP
	copy(b[8:24], net.ParseIP(src).To16())
	copy(b[24:40], net.ParseIP(dst).To16())
	binary.BigEndian.PutUint16(b[40:42], uint16(8+len(payload)))
	copy(b[48:], payload) // after the 40-byte IPv6 + 8-byte UDP headers
	return b
}

func newTestRouter() *peerRouter {
	return newPeerRouter(newPeerTable(nil, 0, "tun-service", nil))
}

// A packet read from the device reaches the peer its destination names, and
// only that peer. Both hops matter: the table resolves the address, the router
// resolves the name to a stream.
func TestP2PDispatchSendsToPeerNamedByDestination(t *testing.T) {
	_, peerAEnd := newDatagramPipe(4)
	_, peerBEnd := newDatagramPipe(4)

	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-a", peerAEnd))
	router.install(newPeerStream(context.Background(), "peer-b", peerBEnd))
	router.table.set(net.ParseIP("10.10.0.3"), "peer-a")

	hub := newP2PHub(nopDevice{}, router, nil, nil)
	pkt := udpPacket("10.10.0.9", "10.10.0.3", 1, 1)
	hub.dispatch(pkt)

	var got [MaxMessageSize]byte
	n, err := peerAEnd.Read(got[:])
	if err != nil {
		t.Fatalf("peer-a read: %v", err)
	}
	if !bytes.Equal(got[:n], pkt) {
		t.Fatalf("peer-a got % x, want % x", got[:n], pkt)
	}

	select {
	case pkt := <-peerBEnd.queue:
		t.Fatalf("peer-b received % x, want nothing", pkt)
	default:
	}
}

// An unroutable destination reports ErrNoRoute rather than failing quietly, so
// dispatch can say which address did not resolve.
func TestP2PDeliverReportsNoRoute(t *testing.T) {
	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-a", discard{closes: new(int)}))

	t.Run("no route", func(t *testing.T) {
		err := router.deliver(net.ParseIP("10.10.0.3"), udpPacket("10.10.0.9", "10.10.0.3", 1, 1))
		if !errors.Is(err, ErrNoRoute) {
			t.Fatalf("deliver = %v, want ErrNoRoute", err)
		}
	})

	t.Run("route but no stream", func(t *testing.T) {
		// A route whose peer has already torn its stream down: the name resolves,
		// nothing is behind it.
		router.table.set(net.ParseIP("10.10.0.3"), "peer-gone")
		err := router.deliver(net.ParseIP("10.10.0.3"), udpPacket("10.10.0.9", "10.10.0.3", 1, 1))
		if !errors.Is(err, ErrNoRoute) {
			t.Fatalf("deliver = %v, want ErrNoRoute for a peer with no stream", err)
		}
	})
}

// IPv6 goes through the other branch of the destination parse, so it gets its
// own case rather than being assumed to work.
func TestP2PDispatchIPv6Destination(t *testing.T) {
	_, peerEnd := newDatagramPipe(4)

	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-a", peerEnd))
	router.table.set(net.ParseIP("fd00::3"), "peer-a")

	hub := newP2PHub(nopDevice{}, router, nil, nil)
	pkt := udp6Packet("fd00::9", "fd00::3", 1, 1)
	hub.dispatch(pkt)

	var got [MaxMessageSize]byte
	n, err := peerEnd.Read(got[:])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got[:n], pkt) {
		t.Fatalf("peer got % x, want % x", got[:n], pkt)
	}
}

// A spoke's datagram reaches the device.
func TestP2PSpokeDatagramReachesDevice(t *testing.T) {
	device := newWriteRecorder(64)
	router := newTestRouter()
	_, peerEnd := newDatagramPipe(4)

	hub := newP2PHub(device, router, nil, nil)
	s := newPeerStream(context.Background(), "peer-a", peerEnd)
	router.install(s)

	pkt := udpPacket("10.10.0.3", "10.10.0.9", 1, 1)
	if err := hub.fromSpoke(s, pkt); err != nil {
		t.Fatalf("fromSpoke: %v", err)
	}

	got := device.received()
	if len(got) != 1 || !bytes.Equal(got[0], pkt) {
		t.Fatalf("device writes = %d entries, want the packet exactly once: % x", len(got), got)
	}
}

// A keepalive is answered *and* registers. The echo is what a keepalive:true
// spoke refreshes its read deadline from, and the registration is what makes the
// peer reachable at all.
func TestP2PKeepaliveIsAnsweredAndRegisters(t *testing.T) {
	const passphrase = "secret"
	device := newWriteRecorder(64)
	_, peerEnd := newDatagramPipe(4)

	table := newPeerTable(newMultiAuther(passphrase, "10.10.0.3"), 0, "tun-service", nil)
	hub := newP2PHub(nopDevice{}, newPeerRouter(table), nil, nil)
	s := newPeerStream(context.Background(), "peer-key-abc", peerEnd)
	hub.router.install(s)

	frame := keepAliveFrame(passphrase, net.ParseIP("10.10.0.3"))
	if err := hub.fromSpoke(s, frame); err != nil {
		t.Fatalf("fromSpoke(keepalive): %v", err)
	}

	var got [MaxMessageSize]byte
	n, err := peerEnd.Read(got[:])
	if err != nil {
		t.Fatalf("no keepalive reply: %v", err)
	}
	if n != keepAliveHeaderLength {
		t.Fatalf("reply is %d bytes, want a %d-byte header", n, keepAliveHeaderLength)
	}
	if !isKeepaliveFrame(got[:n]) {
		t.Fatalf("reply does not carry the magic header: % x", got[:n])
	}

	if name, ok := table.lookup(net.ParseIP("10.10.0.3")); !ok || name != "peer-key-abc" {
		t.Fatalf("lookup = %q, %v, want the registering peer key", name, ok)
	}
	if got := device.received(); len(got) != 0 {
		t.Fatalf("the keepalive was written to the device: % x", got)
	}
}

// A refused registration is not answered: echoing a frame the auther rejected
// would tell the peer it is registered.
func TestP2PRefusedKeepaliveIsNotAnswered(t *testing.T) {
	_, peerEnd := newDatagramPipe(4)

	table := newPeerTable(newMultiAuther("secret", "10.10.0.3"), 0, "tun-service", nil)
	hub := newP2PHub(nopDevice{}, newPeerRouter(table), nil, nil)
	s := newPeerStream(context.Background(), "peer-key", peerEnd)
	hub.router.install(s)

	frame := keepAliveFrame("wrong", net.ParseIP("10.10.0.3"))
	if err := hub.fromSpoke(s, frame); err != nil {
		t.Fatalf("fromSpoke: %v", err)
	}

	select {
	case pkt := <-peerEnd.queue:
		t.Fatalf("a refused registration was answered with % x", pkt)
	default:
	}
	if _, ok := table.lookup(net.ParseIP("10.10.0.3")); ok {
		t.Fatal("a refused registration left a route behind")
	}
}

// newP2PAuthorizerHub builds the hub a deployment gets — NewP2PHandler over the
// tun conn the listener produced — and returns it as the compat suite drives one,
// so a case writes a registration on a real stream and reads the answer off the
// peer's end. Only the authorizer is the case's: the device reader, the stream
// and the route table are the real ones, which is the point of driving the
// handler rather than the table.
//
// The device carries the parsed config, because that is where the hub's own
// addresses live and NewP2PHandler reads them from it (see deviceNets).
//
// The first spoke is registered by the compat harness under peer-key-1, so a case
// that keys an authorizer on a peer name has to know it before the stream exists.
func newP2PAuthorizerHub(t *testing.T, authorizer PeerAuthorizer) *compatP2P {
	t.Helper()

	dev, send, _ := newDevice()
	dctx := ictx.ContextWithMetadata(context.Background(), xmd.NewMetadata(map[string]any{
		"config": &tun_util.Config{Net: compatNets},
	}))

	h := NewP2PHandler(compatTunDevice{compatDevice: dev, ctx: dctx}, authorizer,
		handler.LoggerOption(compatLogger()),
		handler.ServiceOption("tun-service"),
	).(*p2pHandler)

	c := &compatP2P{h: h, router: h.router, send: send}
	t.Cleanup(func() {
		// The streams first: each Close ends the Handle that owns it, and the
		// handler's Close then stops the device reader they were delivering into.
		c.mu.Lock()
		streams := c.streams
		c.mu.Unlock()
		for _, conn := range streams {
			conn.Close()
			<-conn.done
		}
		h.Close()
	})

	return c
}

// End to end through the handler: a claim the authorizer accepts registers its
// address under the peer's key and is answered with the keepalive echo, which is
// the byte a spoke refreshes its read deadline from.
func TestP2PHandleRegistersAnAuthorizedClaim(t *testing.T) {
	assigned := net.ParseIP("10.10.0.3")
	hub := newP2PAuthorizerHub(t, newAssigningAuthorizer(map[string][]net.IP{
		"peer-key-1": {assigned},
	}))

	s := hub.spoke(t)
	_, reply := hub.register(s, keepAliveFrame("secret", assigned))

	// The route first: registering and answering is the whole of a spoke's
	// handshake, and the lookup is what a later packet's delivery resolves.
	if name, ok := hub.resolve(assigned); !ok {
		t.Fatalf("no route for %s after an authorized registration", assigned)
	} else if name != s.name {
		t.Fatalf("the route for %s resolves to %q, want the registering peer %q", assigned, name, s.name)
	}
	if !isKeepaliveFrame(reply) {
		t.Fatalf("the authorized registration was not answered with a keepalive frame: % x", reply)
	}
	if len(reply) != keepAliveHeaderLength {
		t.Fatalf("the reply is %d bytes, want the %d-byte header the spoke detects",
			len(reply), keepAliveHeaderLength)
	}
}

// End to end through the handler: a claim the authorizer refuses registers
// nothing and is not answered.
//
// The route is the load-bearing half of the assertion. A hub that merely stayed
// quiet would pass a reply-only check while still handing its traffic to a peer
// that has no right to the address, so the refusal is asserted where it is
// observable — in the table a packet's destination is resolved against.
func TestP2PHandleDoesNotRegisterARefusedClaim(t *testing.T) {
	assigned := net.ParseIP("10.10.0.3")
	neighbour := net.ParseIP("10.10.0.4")
	hub := newP2PAuthorizerHub(t, newAssigningAuthorizer(map[string][]net.IP{
		"peer-key-1": {assigned},
	}))

	s := hub.spoke(t)
	_, reply := hub.register(s, keepAliveFrame("secret", neighbour))

	if name, ok := hub.resolve(neighbour); ok {
		t.Fatalf("a refused claim left the route %q behind for %s", name, neighbour)
	}
	if reply != nil {
		t.Fatalf("a refused registration was answered with % x", reply)
	}

	// Proof the frame was otherwise acceptable: the same peer claiming the one
	// address it was assigned registers. Without it the refusal above would be
	// indistinguishable from a hub that refuses everything, and the authorizer
	// would go untested.
	_, reply = hub.register(s, keepAliveFrame("secret", assigned))
	if !isKeepaliveFrame(reply) {
		t.Fatalf("the control registration was not answered: % x", reply)
	}
	if name, ok := hub.resolve(assigned); !ok || name != s.name {
		t.Fatalf("the control registration did not take: lookup = %q, %v, want %q", name, ok, s.name)
	}
}

// An unroutable packet is warned about *by destination*. A spoke configured with
// keepalive:0 never registers on a p2p link — the handshake is gated on
// network == "udp" and a p2p link is "ip" — so without the address in the
// warning a misconfigured spoke and a quiet link look identical.
func TestP2PUnroutablePacketWarnsWithDestination(t *testing.T) {
	_, peerEnd := newDatagramPipe(4)

	var mu sync.Mutex
	var warnings []string
	router := newTestRouter()
	hub := newP2PHub(nopDevice{}, router, nil, func(msg string) {
		mu.Lock()
		warnings = append(warnings, msg)
		mu.Unlock()
	})
	// A stream exists for a peer, but this address never registered: exactly
	// what a spoke with keepalive:0 looks like.
	hub.router.install(newPeerStream(context.Background(), "peer-a", peerEnd))

	const dst = "10.10.0.7"
	hub.dispatch(udpPacket("10.10.0.9", dst, 1, 1))

	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warnings)
	}
	if !strings.Contains(warnings[0], dst) {
		t.Fatalf("warning %q does not name the destination %s", warnings[0], dst)
	}
}

// A packet that is neither IPv4 nor IPv6 is an unknown packet, warned about
// rather than routed to whatever the parse happened to return.
func TestP2PUnknownPacketIsWarnedNotRouted(t *testing.T) {
	var warnings []string
	hub := newP2PHub(nopDevice{}, newTestRouter(), nil, func(msg string) {
		warnings = append(warnings, msg)
	})

	hub.dispatch([]byte("not an ip packet"))

	if len(warnings) != 1 || !strings.Contains(warnings[0], "unknown packet") {
		t.Fatalf("warnings = %v, want one unknown-packet warning", warnings)
	}
}

// A stream's teardown drops the routes it owns and leaves another peer's alone.
func TestP2PStreamTeardownDropsItsOwnRoutes(t *testing.T) {
	_, aEnd := newDatagramPipe(4)
	_, bEnd := newDatagramPipe(4)

	router := newTestRouter()
	hub := newP2PHub(nopDevice{}, router, nil, nil)
	a := newPeerStream(context.Background(), "peer-a", aEnd)
	b := newPeerStream(context.Background(), "peer-b", bEnd)
	router.install(a)
	router.install(b)
	aIP, bIP := net.ParseIP("10.10.0.3"), net.ParseIP("10.10.0.4")
	router.table.set(aIP, "peer-a")
	router.table.set(bIP, "peer-b")

	hub.peerGone(a)

	if _, ok := router.table.lookup(aIP); ok {
		t.Fatal("peer-a's route survived its stream's teardown")
	}
	if name, ok := router.table.lookup(bIP); !ok || name != "peer-b" {
		t.Fatalf("peer-b's route = %q, %v, want it untouched", name, ok)
	}
	if s := router.stream("peer-a"); s != nil {
		t.Fatal("peer-a's stream is still installed after teardown")
	}
}

// The reconnect case, and the reason withdraw exists. A peer that reconnects
// installs a second stream under the same name; when the *old* stream's read
// loop finally ends and tears it down, those routes belong to the live
// connection. Dropping them is what makes a flapping peer unreachable rather
// than briefly absent.
func TestP2PStaleStreamTeardownKeepsReconnectingPeerRoute(t *testing.T) {
	_, staleEnd := newDatagramPipe(4)
	_, liveEnd := newDatagramPipe(4)

	router := newTestRouter()
	hub := newP2PHub(nopDevice{}, router, nil, nil)
	stale := newPeerStream(context.Background(), "peer-a", staleEnd)
	live := newPeerStream(context.Background(), "peer-a", liveEnd)
	ip := net.ParseIP("10.10.0.3")
	router.table.set(ip, "peer-a")

	router.install(stale)
	router.install(live) // the reconnect replaces it

	hub.peerGone(stale)

	if name, ok := router.table.lookup(ip); !ok || name != "peer-a" {
		t.Fatalf("lookup = %q, %v, want the reconnecting peer's route to survive", name, ok)
	}
	if s := router.stream("peer-a"); s != live {
		t.Fatal("the stale teardown withdrew the live stream")
	}

	// And the live stream's teardown does reclaim it — otherwise withdraw would
	// be useless and this test would pass for the wrong reason.
	hub.peerGone(live)
	if _, ok := router.table.lookup(ip); ok {
		t.Fatal("the live stream's teardown left the route behind")
	}
	if s := router.stream("peer-a"); s != nil {
		t.Fatal("the live stream is still installed after its teardown")
	}
}

// close is once-only: a stream is torn down from its own read loop and again
// from whoever noticed the delivery fail, and a second Close on a tunnel conn
// aborts a stream a reconnect may already have replaced.
func TestP2PStreamCloseIsIdempotent(t *testing.T) {
	var closes int
	s := newPeerStream(context.Background(), "peer-a", discard{closes: &closes})

	s.close()
	s.close()
	s.close()

	if closes != 1 {
		t.Fatalf("the conn was closed %d times, want 1", closes)
	}
}

// The test the whole device shape rests on. The tun device admits one reader and
// one writer and guarantees neither, so two spokes writing it at once must be
// impossible. Remove the hub's write lock and this fails: the recorder catches
// the overlap, and the spliced packet fails the identity check.
func TestP2PConcurrentSpokeWritesAreIntact(t *testing.T) {
	const (
		rounds = 200
		spokes = 4
		each   = 8
	)

	for round := range rounds {
		device := newWriteRecorder(MaxMessageSize)
		router := newTestRouter()
		hub := newP2PHub(device, router, nil, nil)

		// The exact packet each spoke sends, keyed by tag: a spliced write
		// produces bytes that are not any of these, and a dropped one leaves a
		// tag unaccounted for.
		pkts := make(map[string][]byte, spokes*each)
		for i := range spokes {
			for j := range each {
				pkts[packetKey(i, j)] = udpPacket("10.10.0.3", "10.10.0.9", i, j)
			}
		}

		var wg sync.WaitGroup
		start := make(chan struct{}) // released together, so the writes overlap
		for i := range spokes {
			s := newPeerStream(context.Background(), fmt.Sprintf("peer-%d", i), discard{closes: new(int)})
			router.install(s)

			wg.Add(1)
			go func(i int, s *peerStream) {
				defer wg.Done()
				<-start
				for j := range each {
					if err := hub.fromSpoke(s, pkts[packetKey(i, j)]); err != nil {
						t.Errorf("fromSpoke: %v", err)
						return
					}
				}
			}(i, s)
		}
		close(start)
		wg.Wait()

		if n := device.overlapping(); n != 0 {
			t.Fatalf("round %d: %d writes overlapped inside the device's shared buffer", round, n)
		}

		got := device.received()
		if len(got) != len(pkts) {
			t.Fatalf("round %d: device received %d packets, want %d", round, len(got), len(pkts))
		}
		for _, pkt := range got {
			spoke, seq, ok := tagOf(pkt)
			if !ok {
				t.Fatalf("round %d: device received a packet no spoke sent, spliced: % x", round, pkt)
			}
			key := packetKey(spoke, seq)
			if !bytes.Equal(pkt, pkts[key]) {
				t.Fatalf("round %d: the packet tagged %q was spliced in flight:\n got % x\nwant % x",
					round, key, pkt, pkts[key])
			}
			delete(pkts, key)
		}
		if len(pkts) != 0 {
			t.Fatalf("round %d: %d of the sent packets never arrived", round, len(pkts))
		}
	}
}

// Two goroutines writing one peer's stream must not interleave: the p2p
// datagram conn frames each write onto a byte stream, so two concurrent writes
// put one frame's length prefix against the other's payload, and the reader then
// takes every frame length from the wrong offset. See streamRecorder for why the
// harness is a byte stream and not a pipe.
func TestP2PStreamWritesAreSerialized(t *testing.T) {
	const (
		rounds  = 200
		writers = 4
		each    = 16
	)

	for round := range rounds {
		rec := &streamRecorder{}
		s := newPeerStream(context.Background(), "peer-a", rec)

		pkts := make(map[string][]byte, writers*each)
		for w := range writers {
			for j := range each {
				pkts[packetKey(w, j)] = udpPacket("10.10.0.3", "10.10.0.9", w, j)
			}
		}

		var wg sync.WaitGroup
		start := make(chan struct{}) // released together, so the writes overlap
		for w := range writers {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				<-start
				for j := range each {
					if err := s.write(pkts[packetKey(w, j)]); err != nil {
						t.Errorf("write: %v", err)
						return
					}
				}
			}(w)
		}
		close(start)
		wg.Wait()

		frames, err := rec.frames()
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if len(frames) != writers*each {
			t.Fatalf("round %d: the stream held %d frames, want %d — a length prefix was spliced",
				round, len(frames), writers*each)
		}
		for _, frame := range frames {
			spoke, seq, ok := tagOf(frame)
			if !ok {
				t.Fatalf("round %d: a frame arrived that no writer sent, spliced: % x", round, frame)
			}
			key := packetKey(spoke, seq)
			if !bytes.Equal(frame, pkts[key]) {
				t.Fatalf("round %d: the frame tagged %q was spliced:\n got % x\nwant % x",
					round, key, frame, pkts[key])
			}
			delete(pkts, key)
		}
		if len(pkts) != 0 {
			t.Fatalf("round %d: %d of the sent frames never arrived intact", round, len(pkts))
		}
	}
}

// run is the hub's single device reader: it dispatches every packet the device
// hands it, until the device closes — and reports the close as ErrTun, so a
// deliberate stop stays distinguishable from a failure.
func TestP2PRunDispatchesUntilDeviceCloses(t *testing.T) {
	device, peerEnd := newDatagramPipe(4)

	router := newTestRouter()
	router.install(newPeerStream(context.Background(), "peer-a", peerEnd))
	router.table.set(net.ParseIP("10.10.0.3"), "peer-a")
	hub := newP2PHub(nopDevice{}, router, nil, nil)

	done := make(chan error, 1)
	go func() { done <- hub.run() }()

	pkt := udpPacket("10.10.0.9", "10.10.0.3", 1, 1)
	if _, err := device.Write(pkt); err != nil {
		t.Fatalf("write to the device: %v", err)
	}

	var got [MaxMessageSize]byte
	n, err := peerEnd.Read(got[:])
	if err != nil {
		t.Fatalf("no packet reached the peer: %v", err)
	}
	if !bytes.Equal(got[:n], pkt) {
		t.Fatalf("peer got % x, want % x", got[:n], pkt)
	}

	device.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTun) {
			t.Fatalf("run returned %v, want it to wrap ErrTun", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after the device closed")
	}
}

// The helpers themselves: the keepalive predicate must not claim a packet that
// merely happens to be long enough, and the reply must be exactly the header the
// spoke's client.go detects.
func TestP2PKeepaliveHelpers(t *testing.T) {
	t.Run("a bare header is a keepalive", func(t *testing.T) {
		if !isKeepaliveFrame(keepAliveReply("peer-a")) {
			t.Fatal("the reply the hub sends is not recognized as one")
		}
	})
	t.Run("a registration is a keepalive", func(t *testing.T) {
		if !isKeepaliveFrame(keepAliveFrame("secret", net.ParseIP("10.10.0.3"))) {
			t.Fatal("a registration frame was not recognized")
		}
	})
	t.Run("a packet is not a keepalive", func(t *testing.T) {
		if isKeepaliveFrame(udpPacket("10.10.0.3", "10.10.0.9", 1, 1)) {
			t.Fatal("an ordinary packet was taken for a keepalive")
		}
	})
	t.Run("a short buffer is not a keepalive", func(t *testing.T) {
		if isKeepaliveFrame([]byte("GOST")) {
			t.Fatal("a 4-byte buffer was taken for a keepalive")
		}
		if isKeepaliveFrame(nil) {
			t.Fatal("an empty buffer was taken for a keepalive")
		}
	})
	t.Run("the reply is exactly the header the spoke detects", func(t *testing.T) {
		reply := keepAliveReply("peer-key-abc")
		if len(reply) != keepAliveHeaderLength {
			t.Fatalf("reply is %d bytes, want %d", len(reply), keepAliveHeaderLength)
		}
		if !bytes.HasPrefix(reply, magicHeader) {
			t.Fatalf("reply % x does not start with the magic header", reply)
		}
		if !strings.Contains(string(reply), "peer-key-abc") {
			t.Fatalf("reply % x does not identify the peer", reply)
		}
	})
}

// destinationOf must refuse what the socket server's two loops refuse, and get
// each family's destination right.
func TestP2PDestinationOf(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want string
		ok   bool
	}{
		{"ipv4", udpPacket("10.10.0.3", "10.10.0.9", 1, 1), "10.10.0.9", true},
		{"ipv6", udp6Packet("fd00::3", "fd00::9", 1, 1), "fd00::9", true},
		{"too short", []byte{0x45, 0x00}, "", false},
		{"not ip", []byte("plain text that is long enough to pass a length check"), "", false},
		{"empty", nil, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := destinationOf(tt.pkt)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if !got.Equal(net.ParseIP(tt.want)) {
				t.Fatalf("destination = %s, want %s", got, tt.want)
			}
		})
	}
}

var (
	_ io.ReadWriter  = (*writeRecorder)(nil)
	_ io.WriteCloser = discard{}
)
