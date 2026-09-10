package recorder

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
)

// MinPeriod is the shortest reporting interval a handler may ask for, mirroring
// the floor the observer applies to its own period.
const MinPeriod = time.Second

// Phases a session record can be in: start, interim, and final.
const (
	PhaseStart   = "start"
	PhaseInterim = "interim"
	PhaseFinal   = "final"
)

// ErrReporterClosed is returned when a session outlives the handler that owns it.
var ErrReporterClosed = errors.New("session recorder is closed")

// SessionRecord is one interval record with byte deltas for a session.
type SessionRecord struct {
	HandlerRecorderObject
	SessionID   string `json:"sessionID"`
	RecordIndex uint64 `json:"recordIndex"`
	Phase       string `json:"phase"`
}

// SessionRecorderOptions bounds periodic reporting, delivery, retries, and shutdown.
type SessionRecorderOptions struct {
	Period    time.Duration
	QueueSize int
	// WriteTimeout bounds delivery attempts and queue waits.
	WriteTimeout time.Duration
	// RetryInterval is the pause between delivery attempts of the same record.
	RetryInterval time.Duration
	// DrainTimeout bounds Close: past it the queue is abandoned and Close says so.
	DrainTimeout time.Duration
	Logger       logger.Logger
}

// SessionRecorder samples live sessions and delivers records in order with retries.
type SessionRecorder struct {
	rec  recorder.Recorder
	opts SessionRecorderOptions

	mu       sync.Mutex
	sessions map[*Session]struct{}
	closed   bool

	// admit is held for reading around an enqueue and for writing by Close, so
	// that every enqueue which observed an open reporter completes while the
	// sender is still draining.
	admit sync.RWMutex

	queue     chan []byte
	stop      chan struct{} // closed by Close: no more enqueues, collector stops
	collected chan struct{} // closed by the collector: nothing new will be queued
	done      chan struct{} // closed by the sender: the queue is drained
	ctx       context.Context
	cancel    context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

func NewSessionRecorder(rec recorder.Recorder, opts SessionRecorderOptions) *SessionRecorder {
	if opts.Period > 0 && opts.Period < MinPeriod {
		opts.Period = MinPeriod
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 1024
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 5 * time.Second
	}
	if opts.RetryInterval <= 0 {
		opts.RetryInterval = time.Second
	}
	if opts.DrainTimeout <= 0 {
		opts.DrainTimeout = 30 * time.Second
	}

	r := &SessionRecorder{rec: rec, opts: opts, sessions: make(map[*Session]struct{})}
	if !r.Enabled() {
		return r
	}

	r.queue = make(chan []byte, opts.QueueSize)
	r.stop = make(chan struct{})
	r.collected = make(chan struct{})
	r.done = make(chan struct{})
	r.ctx, r.cancel = context.WithCancel(context.Background())

	go r.collect()
	go r.send()

	return r
}

// Enabled reports whether sessions are sampled periodically. When it is false
// every Session still works, but writes one record when it finishes.
func (r *SessionRecorder) Enabled() bool { return r != nil && r.rec != nil && r.opts.Period > 0 }

// NewSession creates a session over caller-owned cumulative counters.
func (r *SessionRecorder) NewSession(ctx context.Context, counters stats.Stats) *Session {
	s := &Session{sessionRecorder: r, counters: counters, labels: maps.Clone(xctx.LabelsFromContext(ctx))}
	if r.Enabled() {
		s.id = rand.Text()
	}
	return s
}

// Session tracks one connection, HTTP request, or UDP destination.
type Session struct {
	sessionRecorder *SessionRecorder
	counters        stats.Stats
	labels          map[string]string
	id              string

	mu            sync.Mutex
	base          HandlerRecorderObject
	startedAt     time.Time
	last          time.Time
	sequence      uint64
	input, output uint64
	finished      bool
}

// Start stores session metadata and emits one zero-byte start record.
func (s *Session) Start(base HandlerRecorderObject) {
	if s == nil || !s.sessionRecorder.Enabled() {
		return
	}

	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return
	}

	base.HTTP, base.TLS, base.DNS, base.Websocket, base.Redis = nil, nil, nil, nil, nil
	base.Labels = maps.Clone(base.Labels)
	if base.Labels == nil {
		base.Labels = s.labels
	}

	first := s.startedAt.IsZero()
	if first {
		s.startedAt = base.Time
		if s.startedAt.IsZero() {
			s.startedAt = time.Now()
		}
		s.last = s.startedAt
		s.sessionRecorder.watch(s)
	}
	base.Time = s.startedAt
	s.base = base
	if !first {
		s.mu.Unlock()
		return
	}

	start := s.base
	start.InputBytes = 0
	start.OutputBytes = 0
	data, err := s.encode(start, s.startedAt, PhaseStart)
	s.sequence = 1
	s.mu.Unlock()
	if err != nil {
		s.sessionRecorder.logf("encode start: %v", err)
		return
	}
	// A start record is useful metadata, but must never delay establishing a
	// proxy connection when the recorder queue is full. The first interim/final
	// record still carries the complete byte remainder.
	if !s.sessionRecorder.tryEnqueue(data) {
		s.sessionRecorder.logf("queue is full, deferring start record")
		return
	}
}

// Finish seals the session and reports its remaining byte deltas.
func (s *Session) Finish(ctx context.Context, final HandlerRecorderObject) error {
	// A nil recorder preserves the legacy no-op behavior.
	if s == nil || s.sessionRecorder == nil {
		return nil
	}
	r := s.sessionRecorder

	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return nil
	}
	s.finished = true

	if !r.Enabled() {
		s.mu.Unlock()
		// Shutdown cancels connection work before handler defers run. Final
		// recording has its own bounded lifetime even in legacy mode.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.opts.WriteTimeout)
		defer cancel()
		return final.Record(writeCtx, r.rec)
	}

	r.forget(s)

	// An object that was never stamped describes nothing; the legacy recorder
	// drops these too (the outer object of a keep-alive HTTP connection, say).
	if final.Time.IsZero() {
		s.mu.Unlock()
		return nil
	}
	if s.startedAt.IsZero() { // finished before Start, e.g. a failed dial
		s.startedAt, s.last = final.Time, final.Time
	}
	if final.Labels == nil {
		final.Labels = s.labels
	}

	data, err := s.encode(final, time.Now(), PhaseFinal)
	s.mu.Unlock()

	if err != nil {
		return err
	}
	// Enqueued outside the session lock: a busy queue must not stall the
	// collector, which samples every other session on the same goroutine.
	return r.enqueue(data)
}

// encode converts cumulative handler totals into one record's byte deltas.
func (s *Session) encode(ro HandlerRecorderObject, now time.Time, phase string) ([]byte, error) {
	ro.InputBytes = max(ro.InputBytes, s.input) - s.input
	ro.OutputBytes = max(ro.OutputBytes, s.output) - s.output
	ro.Time = now
	ro.Duration = now.Sub(s.last)

	return json.Marshal(SessionRecord{
		HandlerRecorderObject: ro,
		SessionID:             s.id,
		RecordIndex:           s.sequence + 1,
		Phase:                 phase,
	})
}

// report emits the traffic seen since the previous record of this session.
func (s *Session) report(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.finished || s.counters == nil || !now.After(s.last) {
		return
	}
	if s.base.RecordMode == "off" {
		return
	}

	ro := s.base
	ro.InputBytes = s.counters.Get(stats.KindInputBytes)
	ro.OutputBytes = s.counters.Get(stats.KindOutputBytes)
	if ro.InputBytes == s.input && ro.OutputBytes == s.output {
		return // idle interval: an empty record says nothing a later one won't
	}

	data, err := s.encode(ro, now, PhaseInterim)
	if err != nil {
		s.sessionRecorder.logf("encode: %v", err)
		return
	}

	select {
	case s.sessionRecorder.queue <- data:
		// The cursor moves only once the retrying sender owns the record;
		// otherwise a dropped record would take its bytes with it.
		s.input, s.output = ro.InputBytes, ro.OutputBytes
		s.sequence++
		s.last = now
	default:
		// Never block traffic on periodic I/O: fold this interval into the next.
		s.sessionRecorder.logf("queue is full, deferring an interim record")
	}
}

func (r *SessionRecorder) tryEnqueue(data []byte) bool {
	r.admit.RLock()
	defer r.admit.RUnlock()
	select {
	case <-r.stop:
		return false
	case r.queue <- data:
		return true
	default:
		return false
	}
}

func (r *SessionRecorder) watch(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.sessions[s] = struct{}{}
	}
}

func (r *SessionRecorder) forget(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, s)
}

func (r *SessionRecorder) collect() {
	defer close(r.collected)

	ticker := time.NewTicker(r.opts.Period)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			batch := make([]*Session, 0, len(r.sessions))
			for s := range r.sessions {
				batch = append(batch, s)
			}
			r.mu.Unlock()

			for _, s := range batch {
				s.report(now)
			}
		}
	}
}

func (r *SessionRecorder) enqueue(data []byte) error {
	r.admit.RLock()
	defer r.admit.RUnlock()

	// Checked before the blocking select, which would otherwise be free to pick
	// a queue that nothing drains any more.
	select {
	case <-r.stop:
		return ErrReporterClosed
	default:
	}

	// A finished session waits for room, so that a sink which is merely slow
	// costs latency instead of records. The wait is bounded: the caller is a
	// handler defer, and the connection it still holds is not free.
	timer := time.NewTimer(r.opts.WriteTimeout)
	defer timer.Stop()

	select {
	case r.queue <- data:
		return nil
	case <-timer.C:
		return fmt.Errorf("session recorder queue: %w", context.DeadlineExceeded)
	}
}

func (r *SessionRecorder) send() {
	defer close(r.done)

	for {
		select {
		case <-r.ctx.Done():
			return
		case data := <-r.queue:
			if !r.deliver(data) {
				return
			}
		case <-r.collected:
			// Close stops new enqueues and waits for the collector first, so
			// what is in the queue now is all there will ever be.
			for {
				select {
				case data := <-r.queue:
					if !r.deliver(data) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// deliver retries the same body until the recorder takes it, so a backend that
// answers late does not cost the traffic it failed on. It reports false once the
// reporter has given up, which abandons the rest of the queue with it.
func (r *SessionRecorder) deliver(data []byte) bool {
	for {
		ctx, cancel := context.WithTimeout(r.ctx, r.opts.WriteTimeout)
		err := r.rec.Record(ctx, data)
		cancel()
		if err == nil {
			return true
		}
		r.logf("record: %v", err)

		timer := time.NewTimer(r.opts.RetryInterval)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

func (r *SessionRecorder) logf(format string, args ...any) {
	if r.opts.Logger != nil {
		r.opts.Logger.Errorf("session recorder: "+format, args...)
	}
}

// Close stops the reporting tick and delivers what is already queued, within
// DrainTimeout. Sessions still running are the owner's to finish first; an
// incomplete shutdown is reported rather than hidden, so that a sink which
// never recovers delays a restart instead of preventing one.
func (r *SessionRecorder) Close() error {
	if !r.Enabled() {
		return nil
	}

	r.closeOnce.Do(func() {
		r.admit.Lock()
		r.mu.Lock()
		r.closed = true
		active := len(r.sessions)
		r.mu.Unlock()
		close(r.stop)
		r.admit.Unlock()

		timer := time.NewTimer(r.opts.DrainTimeout)
		defer timer.Stop()
		select {
		case <-r.done:
		case <-timer.C:
			r.closeErr = errors.New("session recorder drain timed out")
		}
		r.cancel()

		if active > 0 {
			r.closeErr = errors.Join(r.closeErr, fmt.Errorf("session recorder closed with %d active sessions", active))
		}
	})

	return r.closeErr
}
