package dashboard

import (
	"sync/atomic"
	"time"
)

// connectSeries holds process-cumulative connection counters for one series
// (chain, hop, or node). Metrics are in-process; they reset on config reload
// and do not depend on a metrics service.
type connectSeries struct {
	connects                 atomic.Uint64
	errors                   atomic.Uint64
	connectDurationSumMicros atomic.Uint64
	connectCount             atomic.Uint64
}

func (s *connectSeries) recordSuccess(d time.Duration) {
	s.connects.Add(1)
	s.connectDurationSumMicros.Add(uint64(d.Microseconds()))
	s.connectCount.Add(1)
}

func (s *connectSeries) recordFailure() {
	s.errors.Add(1)
}

func (s *connectSeries) snapshotStats() ChainStats {
	return ChainStats{
		Connects:                 s.connects.Load(),
		Errors:                   s.errors.Load(),
		ConnectDurationSumMicros: s.connectDurationSumMicros.Load(),
		ConnectCount:             s.connectCount.Load(),
	}
}

type hopSeries struct {
	name string
	connectSeries
}

type chainSeries struct {
	connectSeries
	hops  []hopSeries
	nodes map[string]*connectSeries
}

func (s *chainSeries) nodeLocked(name string) *connectSeries {
	if s.nodes == nil {
		s.nodes = make(map[string]*connectSeries)
	}
	if n, ok := s.nodes[name]; ok {
		return n
	}
	s.nodes[name] = &connectSeries{}
	return s.nodes[name]
}

func (s *chainSeries) hopLocked(index int) *hopSeries {
	for len(s.hops) <= index {
		s.hops = append(s.hops, hopSeries{})
	}
	return &s.hops[index]
}

// recordChainHop is the direct-collection recorder. dashboard enablement
// installs it on the chain package; a miss record counts as an error.
func recordChainHop(chainName string, hop int, node string, d time.Duration, err error) {
	Default().recordChainHop(chainName, hop, node, d, err)
}

// recordChainHop records one dial attempt against a hop/node pair.
func (c *Collector) recordChainHop(chainName string, hop int, node string, d time.Duration, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cs := c.chains
	if cs == nil {
		cs = make(map[string]*chainSeries)
		c.chains = cs
	}
	s := cs[chainName]
	if s == nil {
		s = &chainSeries{}
		cs[chainName] = s
	}

	hopS := s.hopLocked(hop)
	hopS.name = node

	ns := s.nodeLocked(node)
	if err == nil {
		hopS.recordSuccess(d)
		ns.recordSuccess(d)
		s.recordSuccess(d)
		return
	}
	hopS.recordFailure()
	ns.recordFailure()
	s.recordFailure()
}

// chainsLocked deep-copies the chain read model for a snapshot, applying
// the configured chain name filter when set.
func (c *Collector) chainsLocked() map[string]ChainSnapshot {
	out := make(map[string]ChainSnapshot, len(c.chains))
	for name, s := range c.chains {
		if c.chainFilter != nil {
			if _, ok := c.chainFilter[name]; !ok {
				continue
			}
		}
		snap := ChainSnapshot{Name: name, Stats: s.snapshotStats()}
		for i := range s.hops {
			hs := &s.hops[i]
			snap.Hops = append(snap.Hops, HopSnapshot{
				Name:  hs.name,
				Nodes: []NodeSnapshot{{Name: hs.name, Stats: hs.snapshotStats()}},
			})
		}
		for node, ns := range s.nodes {
			snap.Nodes = append(snap.Nodes, NodeSnapshot{Name: node, Stats: ns.snapshotStats()})
		}
		out[name] = snap
	}
	return out
}

// SetChainFilter replaces the set of chain names kept by snapshot. A nil set
// disables filtering; an empty non-nil set filters out every chain.
func (c *Collector) SetChainFilter(names map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chainFilter = names
}

// SetConnectionsLimit adjusts the ring capacity. The ring is kept and trimmed
// to fit; passing 0 disables recording.
func (c *Collector) SetConnectionsLimit(limit int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connectionsLimit = limit
	if limit <= 0 {
		return
	}
	for len(c.connections) > limit {
		c.connections = c.connections[1:]
	}
}
