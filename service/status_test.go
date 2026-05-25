package service

import (
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/observer/stats"
)

func TestStatusCreateAndState(t *testing.T) {
	before := time.Now()
	st := &Status{
		createTime: time.Now(),
		events:     make([]Event, 0, MaxEventSize),
	}
	after := time.Now()

	if st.CreateTime().Before(before) || st.CreateTime().After(after) {
		t.Errorf("CreateTime = %v, want between %v and %v", st.CreateTime(), before, after)
	}

	// Initial state is zero value
	if st.State() != State("") {
		t.Errorf("State() = %q, want empty", st.State())
	}

	st.setState(StateReady)
	if got := st.State(); got != StateReady {
		t.Errorf("State() = %q, want %q", got, StateReady)
	}

	st.setState(StateFailed)
	if got := st.State(); got != StateFailed {
		t.Errorf("State() = %q, want %q", got, StateFailed)
	}

	st.setState(StateClosed)
	if got := st.State(); got != StateClosed {
		t.Errorf("State() = %q, want %q", got, StateClosed)
	}
}

func TestStatusStateConcurrency(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
	}

	states := []State{StateRunning, StateReady, StateFailed, StateClosed}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st.setState(states[i%len(states)])
			_ = st.State()
		}(i)
	}
	wg.Wait()
}

func TestStatusEventsEmpty(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
	}

	events := st.Events()
	if len(events) != 0 {
		t.Errorf("Events() = %d events, want 0", len(events))
	}
}

func TestStatusEventsAddAndRetrieve(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
	}

	want := []Event{
		{Time: time.Now(), Message: "event1"},
		{Time: time.Now(), Message: "event2"},
		{Time: time.Now(), Message: "event3"},
	}
	for _, e := range want {
		st.addEvent(e)
	}

	events := st.Events()
	if len(events) != len(want) {
		t.Fatalf("Events() = %d events, want %d", len(events), len(want))
	}
	for i, e := range events {
		if e.Message != want[i].Message {
			t.Errorf("Events()[%d].Message = %q, want %q", i, e.Message, want[i].Message)
		}
	}
}

func TestStatusEventsReturnsCopy(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
	}
	st.addEvent(Event{Message: "original"})

	events := st.Events()
	events[0] = Event{Message: "modified"}

	original := st.Events()
	if original[0].Message != "original" {
		t.Error("Events() should return a copy, internal state was mutated")
	}
}

func TestStatusEventsRingBuffer(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
	}

	// Add MaxEventSize + 5 events; first 5 should be evicted
	for i := 0; i < MaxEventSize+5; i++ {
		st.addEvent(Event{Message: time.Now().Format(time.RFC3339Nano)})
		time.Sleep(time.Microsecond) // ensure unique timestamps
	}

	events := st.Events()
	if len(events) != MaxEventSize {
		t.Fatalf("len(Events()) = %d, want %d", len(events), MaxEventSize)
	}
}

func TestStatusEventsConcurrency(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			st.addEvent(Event{Message: "writer"})
		}()
		go func() {
			defer wg.Done()
			_ = st.Events()
		}()
	}
	wg.Wait()
}

type mockStats struct {
	mu      sync.Mutex
	vals    map[stats.Kind]uint64
	updated bool
}

func newMockStats() *mockStats {
	return &mockStats{vals: make(map[stats.Kind]uint64)}
}

func (m *mockStats) Add(kind stats.Kind, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vals[kind] += uint64(n)
	m.updated = true
}

func (m *mockStats) Get(kind stats.Kind) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vals[kind]
}

func (m *mockStats) IsUpdated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updated
}

func (m *mockStats) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vals = make(map[stats.Kind]uint64)
	m.updated = false
}

func TestStatusStats(t *testing.T) {
	ms := newMockStats()
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
		stats:  ms,
	}

	if got := st.Stats(); got == nil {
		t.Error("Stats() = nil, want non-nil")
	}

	ms.Add(stats.KindTotalConns, 5)
	if got := st.Stats().Get(stats.KindTotalConns); got != 5 {
		t.Errorf("Stats().Get(TotalConns) = %d, want 5", got)
	}
}

func TestStatusStatsNilReceiver(t *testing.T) {
	var st *Status
	if got := st.Stats(); got != nil {
		t.Errorf("nil Stats() = %v, want nil", got)
	}
}

func TestStatusStatsNil(t *testing.T) {
	st := &Status{
		events: make([]Event, 0, MaxEventSize),
		stats:  nil,
	}
	if got := st.Stats(); got != nil {
		t.Errorf("Stats() = %v, want nil", got)
	}
}
