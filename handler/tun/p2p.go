package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	listenertun "github.com/go-gost/x/listener/tun"
)

// ErrNoRoute is what deliver reports when a destination names no peer, or a
// peer with no stream behind it. It is a routing miss and nothing worse: the
// packet is dropped, the hub keeps reading the device.
var ErrNoRoute = errors.New("tun: no route")

// ErrRegistrationRefused reports a spoke registration the hub's policy
// rejected — the authorizer, the passphrase, or the self-loop guard. It is
// returned — never echoed — so the stream is torn down: the spoke redials
// and re-registers (a fixed hub recovers on its own) instead of sitting
// "running" with zero traffic, and the failure surfaces in its counters.
// Nothing is answered, so a refused peer learns nothing except that the
// stream died. Malformed frames and bare echoes are not this: they never
// reach policy, and killing a stream over transport noise would turn one
// stray datagram into a reconnect storm.
var ErrRegistrationRefused = errors.New("tun: registration refused")

// peerStream is the hub's half of one inbound stream from one peer: the peer's
// name, the transport's write side, and the serialization that makes writing
// one packet at a time true.
//
// The lock is not decoration. A p2p datagram conn frames its writes onto a
// byte stream (p2p/internal/host/frame.go appends a 2-byte length, and
// x/p2p/streamconn does the same over the gRPC carrier), and each of those
// serializes only its own read buffer. Two writes to one peer's stream
// therefore interleave one frame's header with the other's payload, and the
// frame lengths are then read from the wrong offset — so the hub never writes
// to a peer stream from two goroutines at once.
//
// close is once-only: a stream is torn down from the read loop that died on it
// and again from whoever notices the failure to deliver, and a second Close on
// a tunnel conn is at best noise and at worst a second abort of a stream a
// reconnect already replaced.
type peerStream struct {
	// key is the peer's name in the route table — a p2p peer key, never an
	// address. ctx is the connection's own: the keepalive registration runs the
	// auther under it, and a plugin auther sends that authentication to an
	// external process, so the lifetime that can cancel it is the connection's,
	// not the hub's.
	ctx  context.Context
	key  string
	w    io.WriteCloser
	once sync.Once

	mu sync.Mutex // serializes writes; see above
}

func newPeerStream(ctx context.Context, key string, w io.WriteCloser) *peerStream {
	return &peerStream{ctx: ctx, key: key, w: w}
}

// write sends p as one datagram on the peer's stream.
func (s *peerStream) write(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.w.Write(p)
	return err
}

func (s *peerStream) close() error {
	var err error
	s.once.Do(func() { err = s.w.Close() })
	return err
}

// peerRouter resolves a route's name to the stream that reaches that peer. It
// is the second delivery alongside the socket server's own: the same table, one
// more answer for "where does this name go".
//
// The map is keyed by name and guarded by its own mutex rather than being a
// sync.Map, because every operation here is a read-modify-write of a pair
// (withdraw only removes s if s is still the holder), and sync.Map offers no
// atomicity across a Load and a Delete.
type peerRouter struct {
	table   *peerTable
	mu      sync.RWMutex
	streams map[string]*peerStream
}

func newPeerRouter(table *peerTable) *peerRouter {
	return &peerRouter{table: table, streams: make(map[string]*peerStream)}
}

// install makes s the stream its key resolves to, replacing whatever was there.
// A peer that reconnected has a new stream under the same name, and the new
// one is the live connection; the old one is on its way out.
func (r *peerRouter) install(s *peerStream) {
	r.mu.Lock()
	r.streams[s.key] = s
	r.mu.Unlock()
}

func (r *peerRouter) stream(key string) *peerStream {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.streams[key]
}

// withdraw removes s, but only if it still holds its key. It reports whether
// it did.
//
// This check is the whole reason the method exists. A peer that reconnects
// installs a new stream under the same name, so when the old stream's read loop
// finally ends and tears it down, the name belongs to the *new* stream: routes
// reclaimed for that name would be reclaimed from the live connection, which is
// what makes a flapping peer unreachable rather than merely briefly absent.
func (r *peerRouter) withdraw(s *peerStream) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.streams[s.key] != s {
		return false
	}
	delete(r.streams, s.key)
	return true
}

// deliver writes pkt on the stream belonging to dst's route. ErrNoRoute when
// the destination is unrouted or the peer it names has no stream.
//
// The name is resolved per delivery, not cached: a lookup is a map read and a
// TTL compare against a packet that already cost a device read, and a peer that
// reconnects must start resolving to the new stream immediately.
func (r *peerRouter) deliver(dst net.IP, pkt []byte) error {
	name, ok := r.table.lookup(dst)
	if !ok {
		return ErrNoRoute
	}

	s := r.stream(name)
	if s == nil {
		return ErrNoRoute
	}
	return s.write(pkt)
}

// deliverFrom is deliver with one more lookup dimension: when no exact route
// owns dst, the prefix table may — a LAN one member sits in front of, routed
// to that member by longest prefix (see peerTable.lookupPrefix). from is the
// packet's requester, the peer an allow list gates: the authenticated stream
// peer on the fromSpoke path; on the dispatch path, where the packet
// originated on the hub's own host, the owner of the source address
// best-effort — the empty key when no member owns it, which no allow list
// names.
//
// The denied cases are ErrNoRoute, not a new error: a requester an allow list
// excludes is as unroutable as a destination no route covers, and deliver's
// callers already account for exactly that.
func (r *peerRouter) deliverFrom(dst net.IP, pkt []byte, from string) error {
	name, ok := r.table.lookupPrefix(dst, from)
	if !ok {
		return ErrNoRoute
	}

	s := r.stream(name)
	if s == nil {
		return ErrNoRoute
	}
	return s.write(pkt)
}

// p2pHub is the p2p hub's device engine: one goroutine reads the tun device,
// and every write to the device — from every peer's stream — goes through one
// lock.
//
// It has to be this shape because the device does not protect itself.
// tunDevice (listener/tun/tun.go) shares one read buffer and one write buffer
// across every call and takes no lock: two readers would have the second
// overwrite the first's target mid-call, and two writers would copy through the
// same write buffer at once. It is safe today only because the socket server
// happens to run exactly one goroutine per side. A p2p hub has one per peer, so
// it has to reach the same guarantee differently — a single reader here, and a
// single lock around every device write below.
//
// Which goroutine read a packet carries no meaning, because the route is what
// says where the packet goes: every spoke's datagram reaches the device by the
// same path, from whatever goroutine its stream is read on.
type p2pHub struct {
	device  io.ReadWriter
	router  *peerRouter
	ownNets []net.IPNet
	warn    func(string)

	// wmu serializes device writes; see above. Reads are not locked because
	// there is only one of them, and it is not this lock's business.
	wmu sync.Mutex

	// dropMu guards the unrouted-packet tally that countUnrouted keeps, so a
	// flood of discards costs one counter increment per packet and one log line
	// per window instead of one line per packet.
	dropMu    sync.Mutex
	dropCount int
	dropDst   string
	dropSince time.Time

	// overMu guards the oversized-packet tally that countOversize keeps. Same
	// shape as the unrouted tally above: the first miss is logged at once, the
	// rest is summarized once per window, so a persistently oversized sender
	// stays visible instead of becoming a silent blackhole.
	overMu    sync.Mutex
	overCount int
	overSince time.Time
}

func newP2PHub(device io.ReadWriter, router *peerRouter, ownNets []net.IPNet, warn func(string)) *p2pHub {
	// A routing miss should not be what panics, same as the table's nil-safe
	// log wrappers.
	if warn == nil {
		warn = func(string) {}
	}
	return &p2pHub{device: device, router: router, ownNets: ownNets, warn: warn}
}

// run is the hub's only device reader. It blocks on Read and dispatches.
//
// It returns the read error, wrapped as ErrTun the way client.go wraps a
// device that closed under its reader, so a deliberate stop stays
// distinguishable from a failure on the way up.
func (h *p2pHub) run() error {
	var b [MaxMessageSize]byte
	for {
		n, err := h.device.Read(b[:])
		if err != nil {
			return errors.Join(ErrTun, err)
		}
		if n == 0 {
			continue
		}
		h.dispatch(b[:n])
	}
}

// dispatch sends one packet from the device to the peer that claimed its
// destination.
//
// It does not collapse the destination to :: the way server.go's findRouteFor
// does for a p2p socket hub. That collapse is right there and wrong here: a
// socket p2p hub has one logical peer, so routing every packet to whoever
// keepalive'd last is the only answer it has, while here a name resolves to one
// specific stream and a spoke is reachable at the address it registered. What a
// p2p hub registers is the installer's call — see server.go's comment on why the
// collapse could not live in peerTable.set, which the socket path shares.
func (h *p2pHub) dispatch(pkt []byte) {
	dst, ok := destinationOf(pkt)
	if !ok {
		h.warnf("unknown packet, discarded(%d)", len(pkt))
		return
	}

	// The requester, for hub-local traffic only. Everything a remote peer
	// sends enters through fromSpoke, where the authenticated stream peer
	// is the requester and the allow gate is enforced before the device; a
	// packet read here originated on the hub's own host, which has no peer
	// key, so the requester is resolved best-effort from the source address
	// — the hub's own stack, trusted in a way a remote sender's source field
	// is not. An unowned source — the hub's own address, which the
	// self-loop guard never lets register, or a host no member claimed —
	// resolves to the empty key.
	from := ""
	if src, ok := sourceOf(pkt); ok {
		if owner, ok := h.router.table.lookup(src); ok {
			from = owner
		}
	}

	// deliverFrom, not deliver: a destination no exact route claims may sit
	// in a LAN one member sits in front of, and the prefix table — consulted
	// only after the exact table misses — names the member that reaches it.
	//
	// The empty requester key is a choice with two edges, both deliberate.
	// An unrestricted route (no allow list) admits it: a host on the LAN
	// behind a spoke is not a member — its address is a LAN address, not
	// any member's tun IP — and LAN-to-LAN through the hub is the very
	// traffic a prefix route exists to carry, so denying no-requester
	// sources would strand exactly that traffic. A restricted route denies
	// it: no allow list names the empty key, so a requester nobody can
	// vouch for never crosses a gate someone drew.
	switch err := h.router.deliverFrom(dst, pkt, from); {
	case errors.Is(err, ErrNoRoute):
		// The destination is named in the warning because a spoke that never
		// registered is otherwise indistinguishable from silence: the
		// registration handshake is gated on network == "udp" (client.go), and a
		// p2p link is "ip", so a spoke configured with keepalive:0 never
		// registers at all.
		//
		// Counted rather than logged per packet: an unrouted destination under
		// load produces one line per packet, which buries every other line and
		// turns a routing gap into a log flood that hides the event that caused
		// it. The first miss is logged immediately (a spoke that never registers
		// must still be visible), and after that the summary carries the count and
		// the span it covers.
		h.countUnrouted(dst)
	case err != nil:
		h.warnf("route %s: %v", dst, err)
	}
}

// unroutedWindow is how long unrouted packets are counted before the summary is
// reported. Long enough that a brief gap is one line, short enough to appear
// within the same log window as the failure that caused it.
const unroutedWindow = 5 * time.Second

// countUnrouted records one unrouted destination and reports the running total
// at most once per window. dst is reported rather than counted per address: a
// hub's unrouted traffic is normally one peer (the one whose route is missing),
// and a map of addresses would be a second routing table to keep honest.
func (h *p2pHub) countUnrouted(dst net.IP) {
	h.dropMu.Lock()
	now := time.Now()
	if h.dropSince.IsZero() {
		h.dropSince = now
		h.dropDst = dst.String()
		h.dropCount = 1
		h.dropMu.Unlock()
		h.warnf("no route for %s, packet discarded", dst)
		return
	}
	h.dropCount++
	// The window only restarts on a report, so a continuous flood reports once
	// per window instead of once per packet.
	if now.Sub(h.dropSince) < unroutedWindow {
		h.dropMu.Unlock()
		return
	}
	n, since, d := h.dropCount, h.dropSince, h.dropDst
	h.dropSince, h.dropCount = now, 0
	h.dropMu.Unlock()
	h.warnf("no route for %s, %d packets discarded in %s", d, n,
		time.Since(since).Round(time.Millisecond).String())
}

// countOversize records one dropped oversized packet and reports the running
// total at most once per window.
func (h *p2pHub) countOversize(size int) {
	h.overMu.Lock()
	now := time.Now()
	if h.overSince.IsZero() {
		h.overSince = now
		h.overCount = 1
		h.overMu.Unlock()
		h.warnf("oversized packet (%d bytes), discarded", size)
		return
	}
	h.overCount++
	// The window only restarts on a report, so a continuous flood reports once
	// per window instead of once per packet.
	if now.Sub(h.overSince) < unroutedWindow {
		h.overMu.Unlock()
		return
	}
	n, since := h.overCount, h.overSince
	h.overSince, h.overCount = now, 0
	h.overMu.Unlock()
	h.warnf("oversized packets discarded: %d in %s", n,
		time.Since(since).Round(time.Millisecond).String())
}

// fromSpoke handles one datagram from one peer: a keepalive is answered on the
// peer it arrived from, a packet for another registered peer is delivered
// straight to that peer's stream, and anything else is the device's.
func (h *p2pHub) fromSpoke(s *peerStream, pkt []byte) error {
	if isKeepaliveFrame(pkt) {
		return h.answerKeepalive(s, pkt)
	}

	// Peer-to-peer shortcut: a destination the table resolves to a live peer
	// reaches it without a round trip through the device and the kernel's
	// same-interface forwarding, which the hub's host may not have enabled.
	// No wmu here: peerStream.write serializes per stream, so direct
	// deliveries never share the device's single write buffer.
	if dst, ok := destinationOf(pkt); ok {
		if name, found := h.router.table.lookup(dst); found {
			if name == s.key {
				// The sender addressed itself: delivering would echo the
				// packet back down the stream it arrived on.
				h.countUnrouted(dst)
				return nil
			}
			if err := h.router.deliver(dst, pkt); err == nil {
				return nil
			} else if errors.Is(err, ErrNoRoute) {
				// The route's stream vanished between lookup and write.
				// Dropping with a count, not a device write the kernel
				// would silently ARP-drop with no warning attached.
				h.countUnrouted(dst)
				return nil
			} else {
				h.warnf("route %s: %v", dst, err)
				return nil
			}
		}

		// The prefix table, consulted only after the exact table misses, and
		// gated on the authenticated stream peer — s.key is the key the
		// registration authenticated, not an address anyone can put in a
		// packet's source field, so an allow list here gates the member the
		// packet actually arrived from. A member outside the route's allow
		// list is denied below, dropped where it stands: sent on to the
		// device instead, the packet would come back through dispatch, whose
		// requester is the source field's owner — self-declared, and able to
		// claim an allow-listed member's address.
		//
		// Delivered directly, like the exact shortcut above, for the same
		// reason: a LAN one member fronts is reached without the kernel's
		// same-interface forwarding.
		if name, found := h.router.table.lookupPrefix(dst, s.key); found {
			if name == s.key {
				// The sender addressed a LAN it itself fronts: delivering
				// would echo the packet back down the stream it arrived on.
				h.countUnrouted(dst)
				return nil
			}
			if err := h.router.deliverFrom(dst, pkt, s.key); err == nil {
				return nil
			} else if errors.Is(err, ErrNoRoute) {
				// The route's stream vanished between lookup and write.
				// Dropping with a count, same as the exact path above.
				h.countUnrouted(dst)
				return nil
			} else {
				h.warnf("route %s: %v", dst, err)
				return nil
			}
		}
		// Covered but refused: a route matches and its allow list excludes
		// the authenticated peer. Denied is unrouted, the same accounting a
		// missing route gets — never a device write, which is the spoof's
		// road back in.
		if h.router.table.prefixCovered(dst) {
			h.countUnrouted(dst)
			return nil
		}
	}

	h.wmu.Lock()
	defer h.wmu.Unlock()

	_, err := h.device.Write(pkt)
	if errors.Is(err, listenertun.ErrPacketTooLarge) {
		// One undeliverable datagram, not a dead device: drop it, count it,
		// and leave the stream up. Returning the error would tear the peer
		// down over a sender-side anomaly and turn it into a reconnect storm.
		h.countOversize(len(pkt))
		return nil
	}
	return err
}

// answerKeepalive registers what the frame claimed and echoes it back on s.
//
// The reply is not optional. The table registers but never writes, because the
// answer has to go back over the transport the frame arrived on — and a p2p
// peer is reachable only on its own stream. The spoke detects the echo
// (client.go) and refreshes its read deadline from any inbound byte, so a hub
// that answers nothing kills every keepalive:true spoke on that spoke's own
// timeout, with nothing to look at in any log.
func (h *p2pHub) answerKeepalive(s *peerStream, pkt []byte) error {
	if _, ok := h.router.table.onKeepalive(s.ctx, pkt, s.key, h.ownNets); !ok {
		if !isRegistrationFrame(pkt) {
			// Transport noise — a bare echo, a fragment — that never
			// reached policy. Drop it and leave the stream up.
			return nil
		}
		return ErrRegistrationRefused
	}

	return s.write(keepAliveReply(s.key))
}

// isRegistrationFrame reports whether pkt is shaped like a registration —
// the parse gates onKeepalive applies before any policy — so the hub can tell
// a refused claim (drop the stream) from transport noise (drop the frame).
func isRegistrationFrame(pkt []byte) bool {
	if len(pkt) <= keepAliveHeaderLength || !bytes.Equal(pkt[:4], magicHeader) {
		return false
	}
	return len(pkt[keepAliveHeaderLength:])%net.IPv6len == 0
}

// peerGone tears a stream down: close it, and reclaim its routes only if it is
// still the stream holding its key. A peer whose reconnect already installed a
// replacement keeps both its routes and its new stream — see withdraw.
func (h *p2pHub) peerGone(s *peerStream) {
	s.close()

	if h.router.withdraw(s) {
		h.router.table.dropPeer(s.key)
	}
}

func (h *p2pHub) warnf(format string, args ...any) {
	h.warn(fmt.Sprintf(format, args...))
}

// isKeepaliveFrame reports whether pkt is the hub's control traffic rather than
// a packet for the device.
//
// A bare 20-byte echo counts as one even though it is not a registration
// (onKeepalive refuses it): it carries the magic header, so writing it to the
// device would inject a 20-byte "packet" that is not one. The alternative —
// letting it fall through — is strictly worse.
func isKeepaliveFrame(b []byte) bool {
	return len(b) >= keepAliveHeaderLength && bytes.Equal(b[:4], magicHeader)
}

// keepAliveReply builds the echo: the magic header, then 16 bytes identifying
// the peer. On the socket path those 16 bytes are the peer's address, which the
// spoke logs; a p2p peer has no address, so its key goes there instead. Only
// the length and the magic are ever read back (client.go), so the field is a
// label and nothing more.
func keepAliveReply(peerKey string) []byte {
	reply := make([]byte, keepAliveHeaderLength)
	copy(reply[:4], magicHeader)
	copy(reply[4:], peerKey)
	return reply
}

// sourceOf parses the source address out of an IP packet, IPv4 or IPv6 —
// the other half of destinationOf, and the address the requester resolution
// in dispatch keys on. Same refusal contract: ok is false for anything that
// is neither or whose header does not parse.
//
// It is a sibling rather than destinationOf returning both because every
// existing caller wants exactly one end of the packet; one function per end
// leaves them all untouched.
func sourceOf(pkt []byte) (net.IP, bool) {
	// waterutil.IsIPv4 indexes packet[0] unconditionally, so an empty buffer —
	// a device that returned no bytes — panics there rather than reporting
	// "unknown packet".
	if len(pkt) == 0 {
		return nil, false
	}

	if waterutil.IsIPv4(pkt) {
		header, err := ipv4.ParseHeader(pkt)
		if err != nil {
			return nil, false
		}
		return header.Src, true
	}

	if waterutil.IsIPv6(pkt) {
		header, err := ipv6.ParseHeader(pkt)
		if err != nil {
			return nil, false
		}
		return header.Src, true
	}

	return nil, false
}

// destinationOf parses the destination address out of an IP packet, IPv4 or
// IPv6. ok is false for anything that is neither or whose header does not parse,
// which is what the socket server's two loops treat as an unknown packet.
func destinationOf(pkt []byte) (net.IP, bool) {
	// waterutil.IsIPv4 indexes packet[0] unconditionally, so an empty buffer —
	// a device that returned no bytes — panics there rather than reporting
	// "unknown packet".
	if len(pkt) == 0 {
		return nil, false
	}

	if waterutil.IsIPv4(pkt) {
		header, err := ipv4.ParseHeader(pkt)
		if err != nil {
			return nil, false
		}
		return header.Dst, true
	}

	if waterutil.IsIPv6(pkt) {
		header, err := ipv6.ParseHeader(pkt)
		if err != nil {
			return nil, false
		}
		return header.Dst, true
	}

	return nil, false
}
