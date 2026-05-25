package service

import (
	"sync"
	"time"

	"github.com/go-gost/core/observer/stats"
)

// MaxEventSize is the maximum number of events retained in a Status event log.
// When the log is full, the oldest event is discarded.
const MaxEventSize = 20

// State represents the operational state of a service.
type State string

const (
	// StateRunning indicates the service has been created but is not yet accepting.
	StateRunning State = "running"
	// StateReady indicates the service is actively accepting connections.
	StateReady State = "ready"
	// StateFailed indicates the service accept loop encountered a temporary error.
	StateFailed State = "failed"
	// StateClosed indicates the service has been shut down.
	StateClosed State = "closed"
)

// Event records a state change or notable occurrence in a service's lifetime.
type Event struct {
	Time    time.Time
	Message string
}

// Status tracks the runtime state, event log, and traffic statistics of a service.
type Status struct {
	createTime time.Time
	state      State
	events     []Event
	stats      stats.Stats
	mu         sync.RWMutex
}

// CreateTime returns the time at which the service was created.
func (p *Status) CreateTime() time.Time {
	return p.createTime
}

// State returns the current service state.
func (p *Status) State() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *Status) setState(state State) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = state
}

// Events returns a snapshot of the recent event log. The returned slice is safe
// to modify without affecting the internal state.
func (p *Status) Events() []Event {
	p.mu.RLock()
	defer p.mu.RUnlock()

	events := make([]Event, len(p.events))
	copy(events, p.events)
	return events
}

func (p *Status) addEvent(event Event) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.events) == MaxEventSize {
		events := make([]Event, MaxEventSize-1, MaxEventSize)
		copy(events, p.events[1:])
		p.events = events
	}
	p.events = append(p.events, event)
}

// Stats returns the traffic statistics for the service. It safely handles nil
// receivers by returning nil.
func (p *Status) Stats() stats.Stats {
	if p == nil {
		return nil
	}
	return p.stats
}
