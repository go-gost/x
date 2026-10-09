package tun

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
)

// peerTable is the hub's destination → peer routing state: it parses a
// keepalive registration, authenticates it, remembers which peer owns which
// addresses, expires a route whose peer went quiet, and answers a destination
// lookup with the peer that claimed it.
//
// It knows nothing about how datagrams arrive. The keepalive protocol, the
// auther check, the TTL and the lookup are the same whether the peer is a UDP
// socket or a p2p stream, so they live here rather than in either transport.
//
// A route's value is a name, not a net.Addr. A UDP peer is named by its address;
// a p2p peer is named by its peer key, which is not an address at all. The table
// only ever hands the name back to the caller, which knows what to do with it.
type peerTable struct {
	// One map, not two. A route's owner is part of the route, so the reverse
	// index that used to answer "which routes are this peer's?" was a second
	// copy of the same fact — and two sync.Maps have no shared atomicity, so
	// concurrent set() calls could leave them disagreeing about who owned an
	// address, after which dropPeer deleted the winner's route. See set.
	routes sync.Map // tunRouteKey -> peerRoute

	// prefixes are the LAN routes the hub installs wholesale — a claim the
	// hub approved, not a fact a keepalive reports — so they are a plain map
	// replaced under mu rather than entries in routes' sync.Map. See
	// SetPrefixRoutes.
	prefixes map[netip.Prefix]PrefixRoute

	// mu guards prefixes. routes needs no lock of its own (its sync.Map is
	// its), and every operation on prefixes is either a wholesale replace or
	// a read-only walk, which is the plain-map-with-RWMutex shape this
	// package already uses for peerRouter.streams.
	mu sync.RWMutex

	auther     auth.Authenticator
	authorizer PeerAuthorizer
	ttl        time.Duration
	service    string
	log        logger.Logger
}

// peerRoute is a registered route: the peer's name and when a keepalive last
// refreshed it, so an absent peer's route can expire.
type peerRoute struct {
	name     string
	lastSeen time.Time
}

// peerTableOption configures a table that the constructor's fixed arguments do
// not express. It is variadic rather than a parameter because a table without an
// authorizer is the common case, and every existing caller means exactly that —
// so "no authorization" is what omitting an option says, without making every
// call site pass a nil.
type peerTableOption func(*peerTable)

// withAuthorizer installs the policy that decides which addresses a peer may
// claim. Without one, a table registers whatever a peer claims.
func withAuthorizer(a PeerAuthorizer) peerTableOption {
	return func(pt *peerTable) { pt.authorizer = a }
}

// newPeerTable builds the table. service is the handler's service name: it is
// passed to the auther on every authentication, and a plugin auther sends it to
// an external process, so dropping it here would silently change who the
// external auther thinks is asking. An empty service is legitimate — a handler
// registered without one — and is passed through as the empty string.
func newPeerTable(auther auth.Authenticator, keepAlivePeriod time.Duration, service string, log logger.Logger, opts ...peerTableOption) *peerTable {
	// ttl is the keepalive period, not the expiry window: a route outlives three
	// missed keepalives (see lookup), which is how server.go has always counted.
	pt := &peerTable{auther: auther, ttl: keepAlivePeriod, service: service, log: log}
	for _, opt := range opts {
		opt(pt)
	}
	return pt
}

// onKeepalive parses a registration frame, authenticates it, and registers the
// peer's addresses under the name from.
//
// from is the transport's name for the sender: a "host:port" for a UDP peer, a
// peer key for a p2p one. It is stored verbatim and never interpreted.
//
// It does not reply. The keepalive echo is part of the transport's own write
// path, and a peer behind a stream is not reachable by writing back here — the
// caller answers, on the same transport the frame arrived on.
func (pt *peerTable) onKeepalive(ctx context.Context, frame []byte, from string, ownNets []net.IPNet) (peerIPs []net.IP, ok bool) {
	// Only a frame carrying at least one address is a registration; a bare
	// 20-byte keepalive echo is the client side acknowledging one.
	if len(frame) <= keepAliveHeaderLength || !bytes.Equal(frame[:4], magicHeader) {
		return nil, false
	}

	// The payload must be a whole number of 16-byte addresses. It has to stay a
	// modulus check rather than a length comparison: the loop below slices
	// data[:net.IPv6len] unconditionally, so any payload this does not reject
	// panics on a wire-reachable input. It also rules out an empty payload,
	// which is why there is no separate check below.
	data := frame[keepAliveHeaderLength:]
	if len(data)%net.IPv6len != 0 {
		return nil, false
	}
	for len(data) > 0 {
		peerIPs = append(peerIPs, net.IP(data[:net.IPv6len]))
		data = data[net.IPv6len:]
	}

	// One of the hub's own networks means the hub is talking to itself, and
	// registering that route would loop its own packets back at itself.
	for _, n := range ownNets {
		for _, ip := range peerIPs {
			if ip.Equal(n.IP.To16()) {
				pt.debugf("keepalive from %v => %v, is this hub itself", from, peerIPs)
				return nil, false
			}
		}
	}

	// Above the auther, deliberately: a claim that is not this peer's to make
	// needs no credential check, and the auther below may be a plugin making an
	// RPC to another process — one not worth spending on a refused claim.
	if pt.authorizer != nil && !pt.authorizer.Authorize(ctx, from, peerIPs) {
		pt.debugf("keepalive from %v => %v, not authorized", from, peerIPs)
		return nil, false
	}

	// The passphrase covers the whole registration, so every claimed address
	// must pass: one address of a frame that must not be half-trusted.
	if pt.auther != nil {
		key := bytes.TrimRight(frame[4:keepAliveHeaderLength], "\x00")
		for _, ip := range peerIPs {
			if _, ok = pt.auther.Authenticate(ctx, ip.String(), string(key), auth.WithService(pt.service)); !ok {
				break
			}
		}
		if !ok {
			pt.debugf("keepalive from %v => %v, auth FAILED", from, peerIPs)
			return nil, false
		}
	}

	for _, ip := range peerIPs {
		pt.set(ip, from)
	}

	pt.debugf("keepalive from %v => %v", from, peerIPs)
	return peerIPs, true
}

// set registers ip under name, refreshing lastSeen if the route already exists.
//
// The route carries its own owner, so the fact dropPeer needs — "is this
// address still this peer's?" — is answered by the value being deleted rather
// than by consulting a second structure. That is what makes it correct: the
// reverse index this used to keep alongside was a second copy of the same
// fact, and two sync.Maps share no atomicity, so two peers claiming one
// address concurrently could leave the index naming a loser whose dropPeer
// then deleted the winner's route. With one map there is nothing to disagree,
// whether this path takes the LoadOrStore path or the Store one.
func (pt *peerTable) set(ip net.IP, name string) {
	rkey := ipToTunRouteKey(ip)
	entry := peerRoute{name: name, lastSeen: time.Now()}
	if actual, loaded := pt.routes.LoadOrStore(rkey, entry); loaded {
		old := actual.(peerRoute)
		pt.routes.Store(rkey, entry) // refresh lastSeen
		if old.name != name {
			pt.debugf("update route: %s -> %s (old %s)", ip, name, old.name)
		}
	} else {
		pt.debugf("new route: %s -> %s", ip, name)
	}
}

// lookup returns the peer name for dst, lazily expiring the route once the TTL
// has passed since its last keepalive. The TTL applies only when a keepalive
// period is configured, so a zero period keeps today's never-expiring routes —
// what an unconfigured socket deployment has always had. No sweeper: every write
// path calls this, which is enough.
func (pt *peerTable) lookup(dst net.IP) (string, bool) {
	rkey := ipToTunRouteKey(dst)
	v, ok := pt.routes.Load(rkey)
	if !ok {
		return "", false
	}
	r := v.(peerRoute)
	// Three missed keepalives, as server.go has always counted them.
	if ttl := pt.ttl * 3; ttl > 0 && time.Since(r.lastSeen) > ttl {
		if pt.routes.CompareAndDelete(rkey, r) {
			// The route and its owner are one value, so expiring the route
			// expires the owner. That pairing used to be maintained here as a
			// second site, which is how the two drifted apart in the first
			// place.
			pt.infof("route expired: %s -> %s", net.IP(rkey[:]), r.name)
		}
		return "", false
	}
	return r.name, true
}

// SetPrefixRoutes replaces the prefix table, deep-copied — the allow lists'
// backing arrays are walked by lookups, so the caller keeps ownership of
// everything it passed and cannot race the walks by mutating it afterwards.
func (pt *peerTable) SetPrefixRoutes(routes map[netip.Prefix]PrefixRoute) {
	cp := make(map[netip.Prefix]PrefixRoute, len(routes))
	for p, r := range routes {
		r.Allow = slices.Clone(r.Allow)
		cp[p] = r
	}
	pt.mu.Lock()
	pt.prefixes = cp
	pt.mu.Unlock()
}

// ipToAddr converts a net.IP to the netip.Addr a prefix Contains. To4
// collapses a 4-byte or a 4-in-6 net.IP to the 4-byte form a v4 prefix
// contains, and leaves a real v6 address alone; without it a 16-byte IPv4
// would never match an IPv4 prefix. ok is false for a slice that is neither
// 4 nor 16 bytes, which no packet header produces.
func ipToAddr(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFromSlice(v4)
	}
	return netip.AddrFromSlice(ip)
}

// lookupPrefix returns the peer owning dst by longest prefix, and whether the
// requesting peer key may use it.
//
// The exact table is consulted first: a member's registered address is that
// member's alone, so a LAN route can never displace or shadow it — a prefix
// is the answer only when no exact route exists. That order is this method,
// not its caller's discipline, so no caller can get it wrong.
//
// A match whose Allow list is non-empty and does not name from is not a
// route: ok is false, the same answer as no match at all.
func (pt *peerTable) lookupPrefix(dst net.IP, from string) (string, bool) {
	if name, ok := pt.lookup(dst); ok {
		return name, true
	}

	addr, ok := ipToAddr(dst)
	if !ok {
		return "", false
	}

	// The walk keeps the longest match rather than returning the first: a
	// hub with 192.168.0.0/16 and 192.168.50.0/24 installed must send a
	// 192.168.50.x packet to the /24's member, not whichever entry the map
	// happened to yield first.
	pt.mu.RLock()
	var (
		best  = -1
		route PrefixRoute
	)
	for p, r := range pt.prefixes {
		if p.Bits() <= best || !p.Contains(addr) {
			continue
		}
		best, route = p.Bits(), r
	}
	pt.mu.RUnlock()
	if best < 0 {
		return "", false
	}

	if len(route.Allow) > 0 && !slices.Contains(route.Allow, from) {
		return "", false
	}
	return route.Peer, true
}

// prefixCovered reports whether any installed prefix contains dst — the match
// lookupPrefix gates, before the gate. A caller that just got ("" ,false)
// from lookupPrefix needs the two cases apart: a destination no route
// covers is the device's to route, while a destination a route covers but
// its allow list refuses must be dropped where it stands — forwarded on to
// the device, its self-declared source could vouch for it there.
func (pt *peerTable) prefixCovered(dst net.IP) bool {
	addr, ok := ipToAddr(dst)
	if !ok {
		return false
	}
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	for p := range pt.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// dropPeer removes every route registered by name, leaving other peers' routes
// alone. The reverse index answers "which routes are this peer's?" without
// scanning the table.
//
// This is the p2p half of reclamation. A socket peer is expired by TTL, guessing
// from silence that it is gone; a stream close says so exactly, so the p2p hub
// calls this when a peer's stream ends and needs no timer at all.
func (pt *peerTable) dropPeer(name string) {
	pt.routes.Range(func(k, v any) bool {
		rkey := k.(tunRouteKey)
		r := v.(peerRoute)
		if r.name != name {
			return true
		}
		pt.infof("route dropped: %s -> %s", net.IP(rkey[:]), r.name)
		// Delete only the entry still owned by name: a peer that took this
		// address over since the scan started must keep its route.
		pt.routes.CompareAndDelete(k, r)
		return true
	})
}

// debugf and infof are nil-safe wrappers: the table is constructed with a nil
// logger in tests, and a routing decision should not be what panics.
func (pt *peerTable) debugf(format string, args ...any) {
	if pt.log == nil {
		return
	}
	pt.log.Debugf(format, args...)
}

func (pt *peerTable) infof(format string, args ...any) {
	if pt.log == nil {
		return
	}
	pt.log.Infof(format, args...)
}
