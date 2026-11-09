package dashboard

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/go-gost/core/observer"
)

// moduleCounters holds cumulative counters for one (kind, name, service)
// series. All fields are atomic so the hot path never takes a lock.
type moduleCounters struct {
	calls        atomic.Uint64
	hits         atomic.Uint64
	misses       atomic.Uint64
	errors       atomic.Uint64
	latencySum   atomic.Uint64
	latencyCount atomic.Uint64

	lastErrReported atomic.Uint64
}

func (c *moduleCounters) snapshot() ModuleStats {
	if c == nil {
		return ModuleStats{}
	}
	return ModuleStats{
		Calls:            c.calls.Load(),
		Hits:             c.hits.Load(),
		Misses:           c.misses.Load(),
		Errors:           c.errors.Load(),
		LatencySumMicros: c.latencySum.Load(),
		LatencyCount:     c.latencyCount.Load(),
	}
}

// seriesEpoch is one generation of the series registry. ResetState swaps the
// whole epoch atomically, so a wrapper from a previous config can never insert
// counters into the new one (no check-then-insert window).
type seriesEpoch struct {
	m sync.Map // Key -> *moduleCounters
}

var seriesEpochs atomic.Pointer[seriesEpoch]

func init() {
	seriesEpochs.Store(&seriesEpoch{})
}

// seriesSet lazily creates one counter per service for a named module.
type seriesSet struct {
	kind      string
	name      string
	epoch     *seriesEpoch
	byService sync.Map // string -> *moduleCounters
	stale     moduleCounters
}

func newSeriesSet(kind, name string) *seriesSet {
	return &seriesSet{
		kind:  kind,
		name:  name,
		epoch: seriesEpochs.Load(),
	}
}

// get returns the counters for a service. sync.Map keeps the hot path
// read-mostly: once a service is seen, Load is allocation-free.
func (s *seriesSet) get(service string) *moduleCounters {
	if s == nil || s.epoch == nil {
		return nil
	}
	if s.epoch != seriesEpochs.Load() {
		return &s.stale
	}
	if v, ok := s.byService.Load(service); ok {
		return v.(*moduleCounters)
	}

	key := Key{Kind: s.kind, Name: s.name, Service: service}
	c := &moduleCounters{}
	actual, _ := s.epoch.m.LoadOrStore(key, c)
	c = actual.(*moduleCounters)
	s.byService.Store(service, c)
	return c
}

// Flush converts every registered series into one cumulative event batch.
// It is safe to call concurrently; repeated calls are idempotent for stats and
// emit at most one error event per increase.
func Flush() {
	if !Enabled() {
		return
	}

	epoch := seriesEpochs.Load()
	if epoch == nil {
		return
	}

	var events []observer.Event
	epoch.m.Range(func(k, v any) bool {
		key, ok := k.(Key)
		if !ok {
			return true
		}
		c, ok := v.(*moduleCounters)
		if !ok || c == nil {
			return true
		}

		stats := c.snapshot()
		events = append(events, ModuleStatsEvent{
			Kind:             key.Kind,
			Name:             key.Name,
			Service:          key.Service,
			Calls:            stats.Calls,
			Hits:             stats.Hits,
			Misses:           stats.Misses,
			Errors:           stats.Errors,
			InputBytes:       stats.InputBytes,
			OutputBytes:      stats.OutputBytes,
			LatencySumMicros: stats.LatencySumMicros,
			LatencyCount:     stats.LatencyCount,
		})

		if stats.Errors > 0 {
			if prev := c.lastErrReported.Swap(stats.Errors); stats.Errors > prev {
				events = append(events, ModuleErrorEvent{
					Kind:    key.Kind,
					Name:    key.Name,
					Service: key.Service,
					Message: errorMessage(key.Kind),
					Seq:     stats.Errors,
				})
			}
		}
		return true
	})

	if len(events) == 0 {
		return
	}
	_ = Default().Observe(context.Background(), events)
}

// errorMessage is deliberately generic: hostnames and addresses must not leak
// into the bounded event ring.
func errorMessage(kind string) string {
	if kind == "" {
		return "module error"
	}
	return kind + " error"
}

// ResetState clears the collector and swaps in an empty series epoch. Config
// reloads call it before the new module instances are constructed.
func ResetState() {
	Default().Reset()
	seriesEpochs.Store(&seriesEpoch{})
}
