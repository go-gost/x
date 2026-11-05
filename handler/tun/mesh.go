package tun

import (
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
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
	MeshStatus() []MeshPeerStatus
	Close() error
}

type meshHandler struct {
	cfg MeshConfig
	log logger.Logger

	mu         sync.RWMutex
	members    map[string]MeshMember
	memberByIP map[netip.Addr]string
	closed     bool
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
	}
}

// Init implements handler.Handler's init contract: the mesh handler has no
// metadata to parse, because its device and membership arrive through methods.
func (h *meshHandler) Init(md.Metadata) error { return nil }

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

// Close stops the handler. It is idempotent; link and device teardown is
// added by the tasks that own them.
func (h *meshHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}
	h.closed = true
	return nil
}

// compile-time check: the handler keeps the membership/status surface.
var _ MeshHandler = (*meshHandler)(nil)
