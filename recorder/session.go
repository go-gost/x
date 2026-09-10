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

// Phases a session record can be in. A start record announces the stream,
// interim records are emitted while it is running, and exactly one final
// record closes it.
const (
	PhaseStart   = "start"
	PhaseInterim = "interim"
	PhaseFinal   = "final"
)

// ErrReporterClosed is returned when a session outlives the handler that owns it.
var ErrReporterClosed = errors.New("session recorder is closed")

// SessionRecord is the periodic handler record. Byte counts are always the delta
// since the previous record of the same session, so a consumer sums them instead
// of replacing what it already stored. A record is identified by (sessionID,
// recordIndex) rather than by SID: one connection can carry several HTTP requests
// or UDP destinations, and a delivery may be retried with the same body.
//
// Time and Duration describe the reported interval; StartedAt and
// SessionDuration describe the session the interval belongs to.
type SessionRecord struct {
	HandlerRecorderObject
	SessionID       string        `json:"sessionID"`
	RecordIndex     uint64        `json:"recordIndex"`
	Phase           string        `json:"phase"`
	StartedAt       time.Time     `json:"startedAt"`
	SessionDuration time.Duration `json:"sessionDuration"`
}

// ReporterOptions bound what a slow or broken recorder can cost. Interim
// records are dropped as soon as the queue is full, since a later one restates
// what they carried; a final record is worth waiting WriteTimeout for, because
// nothing else will report its remainder. Neither ever waits forever: a proxy
// that stops closing connections because its telemetry sink is down is a worse
// outage than the records it would lose.
//
// A nonpositive Period keeps the legacy behaviour: a single record written
// synchronously when the session ends.
type ReporterOptions struct {
	Period    time.Duration
	QueueSize int
	// WriteTimeout bounds one delivery attempt, and how long a finished session
	// waits for room in the queue.
	WriteTimeout time.Duration
	// RetryInterval is the pause between delivery attempts of the same record.
	RetryInterval time.Duration
	// DrainTimeout bounds Close: past it the queue is abandoned and Close says so.
	DrainTimeout time.Duration
	Logger       logger.Logger
}

// SessionReporter owns scheduling and delivery for one handler: a single
// collector samples every live session on the same tick, and a single sender
// delivers the resulting records in order, retrying the byte-for-byte same body
// until the recorder accepts it. The queue lives in memory only, so it survives
// a slow or briefly unavailable backend but not a process restart.
//
// Handlers build one in Init and Close it in Close; everything else goes through
// Session, which is what the protocol code holds.
type SessionReporter struct {
	rec  recorder.Recorder
	opts ReporterOptions

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

func NewSessionReporter(rec recorder.Recorder, opts ReporterOptions) *SessionReporter {
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

	r := &SessionReporter{rec: rec, opts: opts, sessions: make(map[*Session]struct{})}
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
func (r *SessionReporter) Enabled() bool { return r != nil && r.rec != nil && r.opts.Period > 0 }

// NewSession borrows counters that the caller must not reset while the session
// is live: the reporter reads them on its own schedule and turns the cumulative
// totals into deltas. The recorder object is passed in later, by value, so the
// session never shares mutable protocol state with the handler.
func (r *SessionReporter) NewSession(ctx context.Context, counters stats.Stats) *Session {
	s := &Session{reporter: r, counters: counters, labels: maps.Clone(xctx.LabelsFromContext(ctx))}
	if r.Enabled() {
		s.id = rand.Text()
	}
	return s
}

// Session is one accounting stream: a connection, an HTTP request inside it, or
// a single UDP destination. It owns the reporting cursor, independently of the
// recorder object the handler keeps filling in.
type Session struct {
	reporter *SessionReporter
	counters stats.Stats
	labels   map[string]string
	id       string

	mu            sync.Mutex
	base          HandlerRecorderObject
	startedAt     time.Time
	last          time.Time
	sequence      uint64
	input, output uint64
	finished      bool
}

// Start publishes the metadata that interim records carry, once routing and
// authentication have settled it, emits one zero-byte start record, and puts
// the session on the reporting tick.
// It may be called again to refresh that metadata; the session keeps the start
// time it was first given. Protocol bodies and headers are dropped here: they
// describe an exchange, not an interval, and belong to the final record only.
func (s *Session) Start(base HandlerRecorderObject) {
	if s == nil || !s.reporter.Enabled() {
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
		s.reporter.watch(s)
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
		s.reporter.logf("encode start: %v", err)
		return
	}
	// A start record is useful metadata, but must never delay establishing a
	// proxy connection when the recorder queue is full. The first interim/final
	// record still carries the complete byte remainder.
	if !s.reporter.tryEnqueue(data) {
		s.reporter.logf("queue is full, deferring start record")
		return
	}
}

// Finish seals the session and hands over its remainder. final carries the
// session's cumulative totals, exactly as the handler has always computed them:
// callers never subtract what was already reported, the session does that.
//
// With reporting disabled this writes the whole object synchronously, which is
// the legacy contract, errors and all.
func (s *Session) Finish(ctx context.Context, final HandlerRecorderObject) error {
	// A handler that never built a reporter has no recorder to write to either,
	// which is what the legacy path did with a nil recorder: nothing.
	if s == nil || s.reporter == nil {
		return nil
	}
	r := s.reporter

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

// encode turns the cumulative totals in ro into the delta this record carries.
// It leaves the caller's copy alone, so the caller can move the cursor to the
// totals it passed in once the record is safely queued.
//
// Counters are monotonic, but a handler reads its final totals before it calls
// Finish and an interim snapshot can land in between. Clamping that drift keeps
// the race from dropping a final record, which carries the session's metadata,
// over a few bytes.
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
		StartedAt:             s.startedAt,
		SessionDuration:       now.Sub(s.startedAt),
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
		s.reporter.logf("encode: %v", err)
		return
	}

	select {
	case s.reporter.queue <- data:
		// The cursor moves only once the retrying sender owns the record;
		// otherwise a dropped record would take its bytes with it.
		s.input, s.output = ro.InputBytes, ro.OutputBytes
		s.sequence++
		s.last = now
	default:
		// Never block traffic on periodic I/O: fold this interval into the next.
		s.reporter.logf("queue is full, deferring an interim record")
	}
}

func (r *SessionReporter) tryEnqueue(data []byte) bool {
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

func (r *SessionReporter) watch(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.sessions[s] = struct{}{}
	}
}

func (r *SessionReporter) forget(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, s)
}

func (r *SessionReporter) collect() {
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

func (r *SessionReporter) enqueue(data []byte) error {
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

func (r *SessionReporter) send() {
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
func (r *SessionReporter) deliver(data []byte) bool {
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

func (r *SessionReporter) logf(format string, args ...any) {
	if r.opts.Logger != nil {
		r.opts.Logger.Errorf("session recorder: "+format, args...)
	}
}

// Close stops the reporting tick and delivers what is already queued, within
// DrainTimeout. Sessions still running are the owner's to finish first; an
// incomplete shutdown is reported rather than hidden, so that a sink which
// never recovers delays a restart instead of preventing one.
func (r *SessionReporter) Close() error {
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
