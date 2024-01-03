package stats

import (
	"sync"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/x/stats"
)

type HandlerStats struct {
	service string
	stats   map[string]*stats.Stats
	mu      sync.RWMutex
}

func NewHandlerStats(service string) *HandlerStats {
	return &HandlerStats{
		service: service,
		stats:   make(map[string]*stats.Stats),
	}
}

func (p *HandlerStats) Stats(client string) *stats.Stats {
	p.mu.RLock()
	pstats := p.stats[client]
	p.mu.RUnlock()
	if pstats != nil {
		return pstats
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	pstats = p.stats[client]
	if pstats == nil {
		pstats = &stats.Stats{}
	}
	p.stats[client] = pstats

	return pstats
}

func (p *HandlerStats) Events() (events []observer.Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for k, v := range p.stats {
		if !v.IsUpdated() {
			continue
		}
		events = append(events, stats.StatsEvent{
			Kind:         "handler",
			Service:      p.service,
			Client:       k,
			TotalConns:   v.Get(stats.KindTotalConns),
			CurrentConns: v.Get(stats.KindCurrentConns),
			InputBytes:   v.Get(stats.KindInputBytes),
			OutputBytes:  v.Get(stats.KindOutputBytes),
			TotalErrs:    v.Get(stats.KindTotalErrs),
		})
	}
	return
}
