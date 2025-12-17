package tungo

import (
	"sync"
	"time"

	"net/netip"
)

type flowProto uint8

const (
	flowProtoTCP flowProto = 6
	flowProtoUDP flowProto = 17
)

type flowKey struct {
	proto   flowProto
	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16
}

type flowPolicy struct {
	action    string
	useProxy  bool
	proxyHost string
}

type conntrackEntry struct {
	policy    flowPolicy
	expiresAt time.Time
}

type conntrackTable struct {
	mu sync.RWMutex
	m  map[flowKey]conntrackEntry
}

func newConntrackTable() *conntrackTable {
	return &conntrackTable{m: make(map[flowKey]conntrackEntry)}
}

func (t *conntrackTable) Get(now time.Time, k flowKey) (flowPolicy, bool) {
	if t == nil {
		return flowPolicy{}, false
	}

	t.mu.RLock()
	entry, ok := t.m[k]
	t.mu.RUnlock()
	if !ok {
		return flowPolicy{}, false
	}

	if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		t.mu.Lock()
		// re-check under write lock
		if e2, ok2 := t.m[k]; ok2 {
			if !e2.expiresAt.IsZero() && now.After(e2.expiresAt) {
				delete(t.m, k)
			}
		}
		t.mu.Unlock()
		return flowPolicy{}, false
	}

	return entry.policy, true
}

func (t *conntrackTable) Put(now time.Time, k flowKey, p flowPolicy, ttl time.Duration) {
	if t == nil {
		return
	}
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}
	t.mu.Lock()
	t.m[k] = conntrackEntry{policy: p, expiresAt: expiresAt}
	t.mu.Unlock()
}

func (t *conntrackTable) Touch(now time.Time, k flowKey, ttl time.Duration) {
	if t == nil || ttl <= 0 {
		return
	}
	expiresAt := now.Add(ttl)
	t.mu.Lock()
	entry, ok := t.m[k]
	if ok {
		entry.expiresAt = expiresAt
		t.m[k] = entry
	}
	t.mu.Unlock()
}

func (t *conntrackTable) Cleanup(now time.Time) (removed int) {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, entry := range t.m {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(t.m, k)
			removed++
		}
	}
	return removed
}
