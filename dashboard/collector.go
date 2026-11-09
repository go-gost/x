package dashboard

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/observer"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/go-gost/x/service"
)

const (
	defaultHistoryInterval = 5 * time.Second
	defaultHistorySize     = 720 // one hour at 5s
	defaultEventLimit      = 500
	defaultClientLimit     = 4096
)

type options struct {
	historyInterval time.Duration
	historySize     int
	eventLimit      int
	clientLimit     int
	clock           func() time.Time
}

// Option configures a Collector.
type Option func(*options)

// HistoryOption sets the sample interval and the number of samples retained.
func HistoryOption(interval time.Duration, size int) Option {
	return func(o *options) {
		if interval > 0 {
			o.historyInterval = interval
		}
		if size >= 0 {
			o.historySize = size
		}
	}
}

// EventLimitOption sets the maximum number of diagnostic events retained.
func EventLimitOption(n int) Option {
	return func(o *options) {
		if n >= 0 {
			o.eventLimit = n
		}
	}
}

// ClientLimitOption sets the maximum number of per-client handler rows kept
// for one service. The client identifier is internal and never exposed.
func ClientLimitOption(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.clientLimit = n
		}
	}
}

// ClockOption replaces the clock; tests use it to make sampling deterministic.
func ClockOption(fn func() time.Time) Option {
	return func(o *options) {
		if fn != nil {
			o.clock = fn
		}
	}
}

type handlerKey struct {
	Service string
	Client  string
}

type handlerEntry struct {
	stats ServiceStats
	seen  time.Time
}

// Collector aggregates observer events into the dashboard read model. It is
// safe for concurrent use. It deliberately does not implement io.Closer:
// services close the observer they are given, and one collector is shared.
type Collector struct {
	mu           sync.RWMutex
	start        time.Time
	services     map[string]*ServiceSnapshot
	serviceSeen  map[string]bool
	handlers     map[handlerKey]handlerEntry
	handlerCount map[string]int
	modules      map[Key]*ModuleSnapshot
	chains       map[string]*ChainSnapshot
	lastErrorSeq map[Key]uint64
	events       eventRing
	history      historyRing

	historyInterval time.Duration
	clientLimit     int
	clock           func() time.Time
	lastSample      time.Time
}

// NewCollector creates a collector with bounded rings and default limits.
func NewCollector(opts ...Option) *Collector {
	o := options{
		historyInterval: defaultHistoryInterval,
		historySize:     defaultHistorySize,
		eventLimit:      defaultEventLimit,
		clientLimit:     defaultClientLimit,
		clock:           time.Now,
	}
	for _, opt := range opts {
		opt(&o)
	}

	start := o.clock()
	return &Collector{
		start:           start,
		services:        make(map[string]*ServiceSnapshot),
		serviceSeen:     make(map[string]bool),
		handlers:        make(map[handlerKey]handlerEntry),
		handlerCount:    make(map[string]int),
		modules:         make(map[Key]*ModuleSnapshot),
		chains:          make(map[string]*ChainSnapshot),
		lastErrorSeq:    make(map[Key]uint64),
		events:          newEventRing(o.eventLimit),
		history:         newHistoryRing(o.historySize),
		historyInterval: o.historyInterval,
		clientLimit:     o.clientLimit,
		clock:           o.clock,
		lastSample:      start,
	}
}

// Observe implements observer.Observer. It never blocks and always returns
// nil: existing callers retry failed batches, and a retried cumulative batch
// is harmless here because stored values are replaced, not added.
func (c *Collector) Observe(_ context.Context, events []observer.Event, _ ...observer.Option) error {
	now := c.clock()

	c.mu.Lock()
	defer c.mu.Unlock()

	touched := make(map[string]struct{})
	for _, ev := range events {
		switch e := ev.(type) {
		case xstats.StatsEvent:
			c.observeStatsLocked(e, now)
			if e.Kind == "handler" {
				touched[e.Service] = struct{}{}
			}
		case service.ServiceEvent:
			c.serviceLocked(e.Service).State = string(e.State)
		case ModuleStatsEvent:
			m := c.moduleLocked(Key{Kind: e.Kind, Name: e.Name, Service: e.Service})
			m.Stats = ModuleStats{
				Calls:            e.Calls,
				Hits:             e.Hits,
				Misses:           e.Misses,
				Errors:           e.Errors,
				InputBytes:       e.InputBytes,
				OutputBytes:      e.OutputBytes,
				LatencySumMicros: e.LatencySumMicros,
				LatencyCount:     e.LatencyCount,
			}
		case ModuleStateEvent:
			c.moduleLocked(Key{Kind: e.Kind, Name: e.Name, Service: e.Service}).State = e.State
		case ModuleErrorEvent:
			k := Key{Kind: e.Kind, Name: e.Name, Service: e.Service}
			// Retried batches replay the same error; Seq makes it idempotent.
			if e.Seq != 0 && e.Seq <= c.lastErrorSeq[k] {
				continue
			}
			if e.Seq != 0 {
				c.lastErrorSeq[k] = e.Seq
			}
			m := c.moduleLocked(k)
			m.Stats.Errors++
			c.events.add(EventRecord{
				Time:    now,
				Level:   "warn",
				Kind:    e.Kind,
				Name:    e.Name,
				Service: e.Service,
				Message: e.Message,
			})
		}
	}

	// Trim once per batch, not per event: scanning the handler map for every
	// event made eviction quadratic under the write lock.
	for name := range touched {
		c.trimHandlersLocked(name)
	}

	if len(events) > 0 && now.Sub(c.lastSample) >= c.historyInterval {
		c.history.add(c.historyPointLocked(now))
		c.lastSample = now
	}

	return nil
}

func (c *Collector) observeStatsLocked(e xstats.StatsEvent, now time.Time) {
	switch e.Kind {
	case "service":
		s := c.serviceLocked(e.Service)
		s.Stats = ServiceStats{
			TotalConns:   e.TotalConns,
			CurrentConns: e.CurrentConns,
			InputBytes:   e.InputBytes,
			OutputBytes:  e.OutputBytes,
			TotalErrs:    e.TotalErrs,
		}
		c.serviceSeen[e.Service] = true
	case "handler":
		key := handlerKey{Service: e.Service, Client: e.Client}
		if _, ok := c.handlers[key]; !ok {
			c.handlerCount[e.Service]++
		}
		c.handlers[key] = handlerEntry{
			stats: ServiceStats{
				TotalConns:   e.TotalConns,
				CurrentConns: e.CurrentConns,
				InputBytes:   e.InputBytes,
				OutputBytes:  e.OutputBytes,
				TotalErrs:    e.TotalErrs,
			},
			seen: now,
		}
	}
}

// serviceLocked returns the service snapshot, creating it when needed.
func (c *Collector) serviceLocked(name string) *ServiceSnapshot {
	if s := c.services[name]; s != nil {
		return s
	}
	s := &ServiceSnapshot{Name: name}
	c.services[name] = s
	return s
}

func (c *Collector) moduleLocked(k Key) *ModuleSnapshot {
	if m := c.modules[k]; m != nil {
		return m
	}
	m := &ModuleSnapshot{Kind: k.Kind, Name: k.Name, Service: k.Service}
	c.modules[k] = m
	return m
}

// trimHandlersLocked drops the least recently seen handler rows for a service
// when it exceeds the per-service client limit. It runs once per Observe batch,
// so a burst of new clients costs one sort rather than one full scan per event.
func (c *Collector) trimHandlersLocked(service string) {
	count := c.handlerCount[service]
	if count <= c.clientLimit {
		return
	}

	keys := make([]handlerKey, 0, count)
	for k := range c.handlers {
		if k.Service == service {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return c.handlers[keys[i]].seen.Before(c.handlers[keys[j]].seen)
	})

	remove := count - c.clientLimit
	for _, k := range keys {
		if remove == 0 {
			break
		}
		delete(c.handlers, k)
		remove--
	}
	c.handlerCount[service] = c.clientLimit
}

// Snapshot returns an immutable copy of the current read model.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	modules := make([]ModuleSnapshot, 0, len(c.modules))
	for _, m := range c.modules {
		modules = append(modules, *m)
	}
	sort.Slice(modules, func(i, j int) bool {
		if modules[i].Kind != modules[j].Kind {
			return modules[i].Kind < modules[j].Kind
		}
		if modules[i].Service != modules[j].Service {
			return modules[i].Service < modules[j].Service
		}
		return modules[i].Name < modules[j].Name
	})

	chains := make(map[string]ChainSnapshot, len(c.chains))
	for name, ch := range c.chains {
		chains[name] = copyChain(ch)
	}

	services := c.servicesLocked()
	rates := c.ratesLocked()
	for name, s := range services {
		if r, ok := rates[name]; ok {
			s.Rate = r
			services[name] = s
		}
	}

	return Snapshot{
		Version:               1,
		GeneratedAt:           c.clock(),
		StartedAt:             c.start,
		SampleIntervalSeconds: int(c.historyInterval / time.Second),
		Services:              services,
		Modules:               modules,
		Chains:                chains,
		Events:                c.events.list(),
		History:               c.historyLocked(),
	}
}

// ratesLocked derives per-second byte rates from the newest two history
// samples. A service missing from the older sample has no rate yet.
func (c *Collector) ratesLocked() map[string]ServiceRate {
	points := c.history.list()
	if len(points) < 2 {
		return nil
	}

	last, prev := points[len(points)-1], points[len(points)-2]
	dt := last.Time.Sub(prev.Time).Seconds()
	if dt <= 0 {
		return nil
	}

	out := make(map[string]ServiceRate, len(last.Services))
	for name, cur := range last.Services {
		old, ok := prev.Services[name]
		if !ok {
			continue
		}
		out[name] = ServiceRate{
			InputBytesPerSecond:  byteRate(cur.InputBytes, old.InputBytes, dt),
			OutputBytesPerSecond: byteRate(cur.OutputBytes, old.OutputBytes, dt),
		}
	}
	return out
}

func byteRate(cur, prev uint64, seconds float64) float64 {
	if cur < prev {
		return 0
	}
	return float64(cur-prev) / seconds
}

// servicesLocked deep-copies services and folds per-client handler rows into
// services that have no service-level stats.
func (c *Collector) servicesLocked() map[string]ServiceSnapshot {
	out := make(map[string]ServiceSnapshot, len(c.services))
	for name, s := range c.services {
		out[name] = *s
	}
	for key, entry := range c.handlers {
		if c.serviceSeen[key.Service] {
			continue
		}
		s, ok := out[key.Service]
		if !ok {
			s = ServiceSnapshot{Name: key.Service}
		}
		s.Stats.TotalConns += entry.stats.TotalConns
		s.Stats.CurrentConns += entry.stats.CurrentConns
		s.Stats.InputBytes += entry.stats.InputBytes
		s.Stats.OutputBytes += entry.stats.OutputBytes
		s.Stats.TotalErrs += entry.stats.TotalErrs
		out[key.Service] = s
	}
	return out
}

func (c *Collector) historyPointLocked(now time.Time) HistoryPoint {
	services := c.servicesLocked()
	p := HistoryPoint{
		Time:     now,
		Services: make(map[string]ServiceHistory, len(services)),
	}
	for name, s := range services {
		p.Services[name] = ServiceHistory{
			CurrentConns: s.Stats.CurrentConns,
			InputBytes:   s.Stats.InputBytes,
			OutputBytes:  s.Stats.OutputBytes,
		}
	}
	return p
}

func (c *Collector) historyLocked() []HistoryPoint {
	points := c.history.list()
	out := make([]HistoryPoint, 0, len(points))
	for _, p := range points {
		cp := HistoryPoint{
			Time:     p.Time,
			Services: make(map[string]ServiceHistory, len(p.Services)),
		}
		for name, s := range p.Services {
			cp.Services[name] = s
		}
		out = append(out, cp)
	}
	return out
}

func copyChain(ch *ChainSnapshot) ChainSnapshot {
	out := ChainSnapshot{Name: ch.Name, Stats: ch.Stats}
	if len(ch.Hops) > 0 {
		out.Hops = make([]HopSnapshot, len(ch.Hops))
		for i, h := range ch.Hops {
			out.Hops[i] = HopSnapshot{Name: h.Name}
			if len(h.Nodes) > 0 {
				out.Hops[i].Nodes = append([]NodeSnapshot(nil), h.Nodes...)
			}
		}
	}
	return out
}

// Reset clears all series and history while preserving the process start time
// and configured limits. Config reloads call it so services removed or
// reconfigured by the new config do not leave stale state behind.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.services = make(map[string]*ServiceSnapshot)
	c.serviceSeen = make(map[string]bool)
	c.handlers = make(map[handlerKey]handlerEntry)
	c.handlerCount = make(map[string]int)
	c.modules = make(map[Key]*ModuleSnapshot)
	c.chains = make(map[string]*ChainSnapshot)
	c.lastErrorSeq = make(map[Key]uint64)
	c.events = newEventRing(len(c.events.buf))
	c.history = newHistoryRing(len(c.history.buf))
	c.lastSample = c.clock()
}

var enabled atomic.Bool

// Enable turns dashboard collection on or off. It is safe to call from
// configuration reloads.
func Enable(on bool) {
	enabled.Store(on)
}

// Enabled reports whether dashboard collection is on.
func Enabled() bool {
	return enabled.Load()
}

var (
	defaultOnce      sync.Once
	defaultCollector *Collector
)

// Default returns the process-wide collector.
func Default() *Collector {
	defaultOnce.Do(func() {
		defaultCollector = NewCollector()
	})
	return defaultCollector
}
