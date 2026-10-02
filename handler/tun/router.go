package tun

import (
	"bytes"
	"context"
	"net"
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

	auther  auth.Authenticator
	ttl     time.Duration
	service string
	log     logger.Logger
}

// peerRoute is a registered route: the peer's name and when a keepalive last
// refreshed it, so an absent peer's route can expire.
type peerRoute struct {
	name     string
	lastSeen time.Time
}

// newPeerTable builds the table. service is the handler's service name: it is
// passed to the auther on every authentication, and a plugin auther sends it to
// an external process, so dropping it here would silently change who the
// external auther thinks is asking. An empty service is legitimate — a handler
// registered without one — and is passed through as the empty string.
func newPeerTable(auther auth.Authenticator, keepAlivePeriod time.Duration, service string, log logger.Logger) *peerTable {
	// ttl is the keepalive period, not the expiry window: a route outlives three
	// missed keepalives (see lookup), which is how server.go has always counted.
	return &peerTable{auther: auther, ttl: keepAlivePeriod, service: service, log: log}
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
