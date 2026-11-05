package tun

import (
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
	SetMembers(members []MeshMember)
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

// SetMembers replaces the member snapshot. It rebuilds the exact-IP routing
// index; links are reconciled by the task that owns them.
func (h *meshHandler) SetMembers(members []MeshMember) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.members = make(map[string]MeshMember, len(members))
	h.memberByIP = make(map[netip.Addr]string, len(members))
	for _, m := range members {
		if m.Key == "" {
			continue
		}
		h.members[m.Key] = m
		if addr, ok := ipToAddr(m.IP); ok {
			h.memberByIP[addr] = m.Key
		}
	}
}

// MeshStatus reports the hub row first, then members sorted by key. Without
// links every direct-capable member is on the hub; blocked and disabled
// members keep their own states.
func (h *meshHandler) MeshStatus() []MeshPeerStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]MeshPeerStatus, 0, len(h.members)+1)
	out = append(out, MeshPeerStatus{Key: h.cfg.HubKey, State: "hub"})

	keys := make([]string, 0, len(h.members))
	for key := range h.members {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		m := h.members[key]
		state := "hub"
		switch {
		case m.Blocked:
			state = "blocked"
		case m.Disabled:
			state = "disabled"
		case !m.Direct:
			state = "direct-off"
		}

		ips := make([]string, 0, 1)
		if m.IP != nil {
			ips = append(ips, m.IP.String())
		}
		out = append(out, MeshPeerStatus{
			Key:   key,
			Name:  m.Name,
			IPs:   ips,
			State: state,
		})
	}
	return out
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
