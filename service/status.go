package service

import (
	"sync"
	"time"

	"github.com/go-gost/core/observer/stats"
)

const (
	MaxEventSize = 20
)

type State string

const (
	StateRunning State = "running"
	StateReady   State = "ready"
	StateFailed  State = "failed"
	StateClosed  State = "closed"
)

type Event struct {
	Time    time.Time
	Message string
}

type Status struct {
	createTime time.Time
	state      State
	events     []Event
	stats      stats.Stats
	mu         sync.RWMutex
}

func (p *Status) CreateTime() time.Time {
	return p.createTime
}

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

func (p *Status) Events() []Event {
	events := make([]Event, MaxEventSize)

	p.mu.RLock()
	defer p.mu.RUnlock()

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

func (p *Status) Stats() stats.Stats {
	if p == nil {
		return nil
	}
	return p.stats
}
