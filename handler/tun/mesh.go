package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	tun_util "github.com/go-gost/x/internal/util/tun"
	listenertun "github.com/go-gost/x/listener/tun"
	xlogger "github.com/go-gost/x/logger"
)

// MeshMember is one member of a spoke's tun network, as the mesh handler
// routes by. Direct/Blocked/Disabled are local policy inputs; the hub's
// netview drives them.
type MeshMember struct {
	IP       net.IP
	Key      string
	Name     string
	Direct   bool
	Blocked  bool
	Disabled bool
}

// MeshCloseReason says why a link went away, so the manager redials only the
// closes that a new dial can fix.
type MeshCloseReason string

const (
	MeshCloseRemote     MeshCloseReason = "remote"
	MeshCloseUnhealthy  MeshCloseReason = "unhealthy"
	MeshCloseWrite      MeshCloseReason = "write"
	MeshCloseDial       MeshCloseReason = "dial"
	MeshCloseIdle       MeshCloseReason = "idle"
	MeshCloseDedup      MeshCloseReason = "dedup"
	MeshCloseMembership MeshCloseReason = "membership"
	MeshCloseBlocked    MeshCloseReason = "blocked"
	MeshCloseShutdown   MeshCloseReason = "shutdown"
)

// MeshPeerStatus is one row of the spoke's peer list: the hub first, then the
// members. Transport/underlay is joined by wisper from the p2p host status; the
// handler only knows the local link state.
type MeshPeerStatus struct {
	Key           string
	Name          string
	IPs           []string
	State         string // direct / connecting / hub / blocked / disabled / direct-off
	DialedLocally bool
	Since         time.Time
	LastInbound   time.Time
	BytesIn       uint64
	BytesOut      uint64

	BlockedPackets uint64
	BlockedBytes   uint64
}

// MeshConfig is the fixed identity and device address set of a mesh handler.
// The device itself arrives later, one conn at a time, through RunDevice.
type MeshConfig struct {
	LocalKey string
	HubKey   string
	// LocalIPs are this device's own tun addresses. They are the addresses a
	// direct inbound packet may target, and the addresses this side registers
	// with each peer.
	LocalIPs []net.IP
}

// MeshHandler is the subset of the mesh handler's surface needed by its
// owner. Later tasks extend it with the handler.Handler contract and the link
// installation/status methods.
type MeshHandler interface {
	handler.Handler
	RunDevice(conn net.Conn) error
	SetMembers(members []MeshMember)
	SetHubLink(conn net.Conn)
	AddDialedLink(peer string, conn net.Conn)
	DropLink(peer string)
	SetDirectNeeded(func(peer string))
	SetLinkClosed(func(peer string, reason MeshCloseReason))
	MeshStatus() []MeshPeerStatus
	Close() error
}

type meshHandler struct {
	cfg MeshConfig
	log logger.Logger

	mu         sync.RWMutex
	members    map[string]MeshMember
	memberIPs  map[string][]net.IP
	memberByIP map[netip.Addr]string
	links      map[string]*meshLink
	hub        *meshLink
	device     net.Conn
	closed     bool

	directNeeded func(peer string)
	linkClosed   func(peer string, reason MeshCloseReason)

	wmu sync.Mutex

	countNonIP               atomic.Int64
	countLoop                atomic.Int64
	countNoRoute             atomic.Int64
	countDirectFallback      atomic.Int64
	countQueueFull           atomic.Int64
	countOversize            atomic.Int64
	countBlocked             atomic.Int64
	countDisabled            atomic.Int64
	countForeignSrc          atomic.Int64
	countForeignDst          atomic.Int64
	countRegistrationRefused atomic.Int64
}

// NewMeshHandler builds an inert mesh handler: it owns no device and no links
// until RunDevice and the link installation methods are called. A nil logger
// falls back to a discarding logger, so a test or a partially configured
// process cannot panic on the first drop.
func NewMeshHandler(cfg MeshConfig, opts ...handler.Option) MeshHandler {
	var options handler.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := options.Logger
	if log == nil {
		log = xlogger.Nop()
	}

	return &meshHandler{
		cfg:        cfg,
		log:        log,
		members:    make(map[string]MeshMember),
		memberIPs:  make(map[string][]net.IP),
		memberByIP: make(map[netip.Addr]string),
		links:      make(map[string]*meshLink),
	}
}

// SetDirectNeeded installs the on-demand dial callback. It is called from the
// device reader, so the owner must return quickly (the wisper manager coalesces
// attempts and does the dialing off this goroutine).
func (h *meshHandler) SetDirectNeeded(fn func(peer string)) {
	h.mu.Lock()
	h.directNeeded = fn
	h.mu.Unlock()
}

// SetLinkClosed installs the link teardown callback. Shutdown closes are not
// reported; every other close carries its reason.
func (h *meshHandler) SetLinkClosed(fn func(peer string, reason MeshCloseReason)) {
	h.mu.Lock()
	h.linkClosed = fn
	h.mu.Unlock()
}

// Init implements handler.Handler's init contract: the mesh handler has no
// metadata to parse, because its device and membership arrive through methods.
func (h *meshHandler) Init(md.Metadata) error { return nil }

// errDeviceBusy rejects a second device while one is still being read; the
// entrypoint supervisor is sequential, so this is a programming error rather
// than a recoverable state.
var errDeviceBusy = errors.New("tun: mesh device already active")

// RunDevice owns one tun device and blocks until it closes. Links and
// membership survive the call; the next call takes the replacement device.
func (h *meshHandler) RunDevice(conn net.Conn) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrTun
	}
	if h.device != nil && h.device != conn {
		h.mu.Unlock()
		return errDeviceBusy
	}
	h.device = conn
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		if h.device == conn {
			h.device = nil
		}
		h.mu.Unlock()
	}()

	buf := make([]byte, MaxMessageSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			h.dispatch(buf[:n])
		}
		if err != nil {
			return errors.Join(ErrTun, err)
		}
	}
}

// dispatch routes one packet from the device without ever writing a link
// synchronously. The device reader must stay responsive even when a direct
// peer stopped reading.
func (h *meshHandler) dispatch(pkt []byte) {
	dst, ok := destinationOf(pkt)
	if !ok {
		h.countNonIP.Add(1)
		return
	}
	if h.isLocalIP(dst) {
		h.countLoop.Add(1)
		return
	}

	addr, ok := ipToAddr(dst)
	if !ok {
		h.countNonIP.Add(1)
		return
	}

	h.mu.RLock()
	key, memberOK := h.memberByIP[addr]
	member := h.members[key]
	hub := h.hub
	link := h.links[key]
	notify := h.directNeeded
	h.mu.RUnlock()

	if memberOK {
		switch {
		case member.Blocked:
			h.countBlocked.Add(1)
			return
		case member.Disabled:
			h.countDisabled.Add(1)
			return
		}

		if member.Direct {
			ready := link != nil && link.ready.Load()
			if ready && link.enqueue(pkt) {
				return
			}
			if ready {
				h.countDirectFallback.Add(1)
			} else if notify != nil {
				notify(key)
			}
		}
	}

	if hub != nil {
		if hub.enqueue(pkt) {
			return
		}
		h.countQueueFull.Add(1)
		return
	}
	h.countNoRoute.Add(1)
}

// writeDevice serializes every inbound write to the current device. A write
// that arrives while no device is attached (a close or a replacement gap) is
// dropped rather than delivered to a stale descriptor.
func (h *meshHandler) writeDevice(pkt []byte) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()

	h.mu.RLock()
	device := h.device
	h.mu.RUnlock()
	if device == nil {
		return ErrTun
	}

	_, err := device.Write(pkt)
	if errors.Is(err, listenertun.ErrPacketTooLarge) {
		h.countOversize.Add(1)
		return nil
	}
	return err
}

func (h *meshHandler) isLocalIP(ip net.IP) bool {
	for _, local := range h.cfg.LocalIPs {
		if ip.Equal(local) {
			return true
		}
	}
	return false
}

// SetHubLink installs the permanent fallback link. The hub link never joins the
// direct-link dedupe set, and its close is reported so the manager can redial.
func (h *meshHandler) SetHubLink(conn net.Conn) {
	if conn == nil {
		return
	}
	l := newMeshLink(h.cfg.HubKey, conn, true, true, func(l *meshLink, reason MeshCloseReason) {
		h.removeLink(l, reason, true)
	})

	h.mu.Lock()
	old := h.hub
	h.hub = l
	h.mu.Unlock()
	if old != nil {
		old.close(MeshCloseShutdown)
	}

	l.start(nil, meshRegistrationFrame(h.cfg.LocalIPs), h.handleHubFrame)
}

// AddDialedLink installs a direct link the manager opened on demand.
func (h *meshHandler) AddDialedLink(peer string, conn net.Conn) {
	if conn == nil {
		return
	}

	h.mu.RLock()
	m, ok := h.members[peer]
	localKey, hubKey := h.cfg.LocalKey, h.cfg.HubKey
	h.mu.RUnlock()
	if !ok || peer == localKey || peer == hubKey || !m.Direct || m.Blocked || m.Disabled {
		_ = conn.Close()
		return
	}

	l := newMeshLink(peer, conn, true, false, func(l *meshLink, reason MeshCloseReason) {
		h.removeLink(l, reason, false)
	})
	h.installLink(l)
	l.start(nil, meshRegistrationFrame(h.cfg.LocalIPs), func(pkt []byte) error {
		return h.handleDirectFrame(l, pkt)
	})
}

// DropLink closes the current direct link for peer, if any.
func (h *meshHandler) DropLink(peer string) {
	h.mu.RLock()
	l := h.links[peer]
	h.mu.RUnlock()
	if l != nil {
		l.close(MeshCloseMembership)
	}
}

// installLink makes l the current direct link for its peer, subject to the
// dedupe preference. It returns whether l won; a loser is closed with dedup.
func (h *meshHandler) installLink(l *meshLink) bool {
	h.mu.Lock()
	old := h.links[l.key]
	if old != nil && old != l && !meshLinkPreferred(l, old, h.cfg.LocalKey) {
		h.mu.Unlock()
		l.close(MeshCloseDedup)
		return false
	}
	h.links[l.key] = l
	h.mu.Unlock()
	if old != nil && old != l {
		old.close(MeshCloseDedup)
	}
	return true
}

// meshLinkPreferred keeps the link whose dialer key is lexicographically
// smaller. Both ends compute the same winner, so a simultaneous dial converges
// on one physical stream. An equal dialer keeps the existing link.
func meshLinkPreferred(incoming, existing *meshLink, localKey string) bool {
	return meshDialer(incoming, localKey) < meshDialer(existing, localKey)
}

func meshDialer(l *meshLink, localKey string) string {
	if l.dialedLocally {
		return localKey
	}
	return l.key
}

// removeLink retires l only if it is still the current link for its key. A
// dedupe loser was never current, but its callback is still reported: the
// manager needs to know that the attempt it started lost, and ignores dedup.
func (h *meshHandler) removeLink(l *meshLink, reason MeshCloseReason, hub bool) {
	h.mu.Lock()
	current := false
	if hub {
		if h.hub == l {
			h.hub = nil
			current = true
		}
	} else if h.links[l.key] == l {
		delete(h.links, l.key)
		current = true
	}
	cb := h.linkClosed
	h.mu.Unlock()

	if reason == MeshCloseShutdown || cb == nil {
		return
	}
	if current || reason == MeshCloseDedup {
		cb(l.key, reason)
	}
}

// Handle runs one inbound direct stream for as long as it lives. The stream is
// accepted only for a direct-capable member, and only after its first frame
// proves it is tun traffic.
func (h *meshHandler) Handle(ctx context.Context, conn net.Conn, _ ...handler.HandleOption) error {
	if conn == nil {
		return nil
	}

	peer := conn.RemoteAddr().String()
	h.mu.RLock()
	m, ok := h.members[peer]
	localKey, hubKey := h.cfg.LocalKey, h.cfg.HubKey
	h.mu.RUnlock()
	if !ok || peer == localKey || peer == hubKey || !m.Direct || m.Blocked || m.Disabled {
		_ = conn.Close()
		return nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(meshFirstInboundTimeout))
	buf := make([]byte, MaxMessageSize)
	n, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return err
	}
	if n == 0 || !isTunFrame(buf[:n]) {
		_ = conn.Close()
		return nil
	}
	first := append([]byte(nil), buf[:n]...)

	l := newMeshLink(peer, conn, false, false, func(l *meshLink, reason MeshCloseReason) {
		h.removeLink(l, reason, false)
	})
	if !h.installLink(l) {
		return nil
	}
	l.start(first, meshRegistrationFrame(h.cfg.LocalIPs), func(pkt []byte) error {
		return h.handleDirectFrame(l, pkt)
	})

	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		l.close(MeshCloseShutdown)
		return ctx.Err()
	}
}

func (h *meshHandler) handleHubFrame(pkt []byte) error {
	if isKeepaliveFrame(pkt) {
		return nil
	}
	if !tun_util.IPv4Packet(pkt) && !tun_util.IPv6Packet(pkt) {
		h.countNonIP.Add(1)
		return nil
	}
	return h.writeDevice(pkt)
}

func (h *meshHandler) handleDirectFrame(link *meshLink, pkt []byte) error {
	if isKeepaliveFrame(pkt) {
		if len(pkt) == keepAliveHeaderLength {
			return nil // an echo; the link's reader already marked it inbound
		}
		if isRegistrationFrame(pkt) {
			if !meshValidRegistration(h.memberIPsFor(link.key), pkt) {
				h.countRegistrationRefused.Add(1)
				link.close(MeshCloseMembership)
				return nil
			}
			if err := link.writeFrame(keepAliveReply(link.key)); err != nil {
				link.close(MeshCloseWrite)
			}
			return nil
		}
		return nil
	}

	if !tun_util.IPv4Packet(pkt) && !tun_util.IPv6Packet(pkt) {
		h.countNonIP.Add(1)
		return nil
	}
	src, ok := sourceOf(pkt)
	if !ok {
		h.countNonIP.Add(1)
		return nil
	}
	if !ipIn(src, h.memberIPsFor(link.key)) {
		h.countForeignSrc.Add(1)
		return nil
	}
	dst, ok := destinationOf(pkt)
	if !ok {
		h.countNonIP.Add(1)
		return nil
	}
	if !h.isLocalIP(dst) {
		h.countForeignDst.Add(1)
		return nil
	}
	return h.writeDevice(pkt)
}

func (h *meshHandler) memberIPsFor(peer string) []net.IP {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]net.IP(nil), h.memberIPs[peer]...)
}

func ipIn(ip net.IP, ips []net.IP) bool {
	for _, candidate := range ips {
		if ip.Equal(candidate) {
			return true
		}
	}
	return false
}

// meshRegistrationFrame builds the registration/keepalive frame a mesh link
// sends: the GOST magic, an empty passphrase, then this device's addresses.
func meshRegistrationFrame(localIPs []net.IP) []byte {
	b := make([]byte, keepAliveHeaderLength+len(localIPs)*net.IPv6len)
	copy(b[:4], magicHeader)
	pos := keepAliveHeaderLength
	for _, ip := range localIPs {
		copy(b[pos:pos+net.IPv6len], ip.To16())
		pos += net.IPv6len
	}
	return b
}

// meshValidRegistration reports whether frame claims exactly the addresses
// assigned to the peer — the same set-equality rule the hub applies.
func meshValidRegistration(ips []net.IP, frame []byte) bool {
	if !isRegistrationFrame(frame) {
		return false
	}
	claimed := frame[keepAliveHeaderLength:]
	if len(claimed) != len(ips)*net.IPv6len {
		return false
	}
	matched := make([]bool, len(ips))
	for len(claimed) > 0 {
		ip := net.IP(claimed[:net.IPv6len])
		found := false
		for i, candidate := range ips {
			if !matched[i] && ip.Equal(candidate) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
		claimed = claimed[net.IPv6len:]
	}
	return true
}

// SetMembers replaces the member snapshot. It rebuilds the exact-IP routing
// index and retires links no longer allowed by the new policy. The hub link is
// untouched: it is the fallback, not a member link.
func (h *meshHandler) SetMembers(members []MeshMember) {
	h.mu.Lock()
	h.members = make(map[string]MeshMember, len(members))
	h.memberIPs = make(map[string][]net.IP, len(members))
	h.memberByIP = make(map[netip.Addr]string, len(members))
	for _, m := range members {
		if m.Key == "" {
			continue
		}
		h.members[m.Key] = m
		if m.IP == nil {
			continue
		}
		h.memberIPs[m.Key] = append(h.memberIPs[m.Key], m.IP)
		if addr, ok := ipToAddr(m.IP); ok {
			h.memberByIP[addr] = m.Key
		}
	}

	var membership, blocked []*meshLink
	for key, l := range h.links {
		m, ok := h.members[key]
		switch {
		case !ok || !m.Direct || m.Disabled:
			membership = append(membership, l)
		case m.Blocked:
			blocked = append(blocked, l)
		}
	}
	h.mu.Unlock()

	for _, l := range membership {
		l.close(MeshCloseMembership)
	}
	for _, l := range blocked {
		l.close(MeshCloseBlocked)
	}
}

// MeshStatus reports the hub row first, then members sorted by key. Without
// links every direct-capable member is on the hub; blocked and disabled
// members keep their own states.
func (h *meshHandler) MeshStatus() []MeshPeerStatus {
	h.mu.RLock()
	members := make(map[string]MeshMember, len(h.members))
	for key, m := range h.members {
		members[key] = m
	}
	memberIPs := make(map[string][]net.IP, len(h.memberIPs))
	for key, ips := range h.memberIPs {
		memberIPs[key] = append([]net.IP(nil), ips...)
	}
	hub := h.hub
	links := make(map[string]*meshLink, len(h.links))
	for key, l := range h.links {
		links[key] = l
	}
	hubKey := h.cfg.HubKey
	h.mu.RUnlock()

	out := make([]MeshPeerStatus, 0, len(members)+1)
	hubRow := MeshPeerStatus{Key: hubKey, State: "hub"}
	if hub != nil {
		hubRow.DialedLocally = hub.dialedLocally
		hubRow.Since = hub.since
		hubRow.LastInbound = meshLastInbound(hub)
		hubRow.BytesIn = hub.bytesIn.Load()
		hubRow.BytesOut = hub.bytesOut.Load()
	}
	out = append(out, hubRow)

	keys := make([]string, 0, len(members))
	for key := range members {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		m := members[key]
		state := "hub"
		switch {
		case m.Blocked:
			state = "blocked"
		case m.Disabled:
			state = "disabled"
		case !m.Direct:
			state = "direct-off"
		}

		ips := make([]string, 0, len(memberIPs[key]))
		for _, ip := range memberIPs[key] {
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}
		sort.Strings(ips)

		row := MeshPeerStatus{
			Key:   key,
			Name:  m.Name,
			IPs:   ips,
			State: state,
		}
		if l := links[key]; l != nil {
			row.DialedLocally = l.dialedLocally
			row.Since = l.since
			row.LastInbound = meshLastInbound(l)
			row.BytesIn = l.bytesIn.Load()
			row.BytesOut = l.bytesOut.Load()
			switch state {
			case "hub":
				row.State = "connecting"
				if l.ready.Load() {
					row.State = "direct"
				}
			case "direct-off":
				// A link for a member that no longer advertises direct is stale;
				// keep the policy state visible until SetMembers retires it.
			}
		}
		out = append(out, row)
	}
	return out
}

func meshLastInbound(l *meshLink) time.Time {
	ns := l.lastInbound.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Close stops the handler. It is idempotent; links and the device are closed
// once, and a shutdown close does not notify the manager.
func (h *meshHandler) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	device := h.device
	h.device = nil
	hub := h.hub
	h.hub = nil
	links := make([]*meshLink, 0, len(h.links))
	for _, l := range h.links {
		links = append(links, l)
	}
	h.links = make(map[string]*meshLink)
	h.mu.Unlock()

	if hub != nil {
		hub.close(MeshCloseShutdown)
	}
	for _, l := range links {
		l.close(MeshCloseShutdown)
	}
	if device != nil {
		_ = device.Close()
	}
	return nil
}

// compile-time check: the handler keeps the membership/status surface.
var _ MeshHandler = (*meshHandler)(nil)
var _ handler.Handler = (*meshHandler)(nil)
