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

	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
)

const MinPeriod = time.Second

var ErrSessionRecorderClosed = errors.New("session recorder is closed")

type SessionRecorderOptions struct {
	Period       time.Duration
	WriteTimeout time.Duration
}

type SessionRecorder struct {
	rec  recorder.Recorder
	opts SessionRecorderOptions

	stop chan struct{}
	done chan struct{}

	mu       sync.Mutex
	sessions map[*Session]struct{}
	closed   bool

	closeOnce sync.Once
	closeErr  error
}

func NewSessionRecorder(rec recorder.Recorder, opts SessionRecorderOptions) *SessionRecorder {
	if opts.Period > 0 && opts.Period < MinPeriod {
		opts.Period = MinPeriod
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 5 * time.Second
	}

	r := &SessionRecorder{rec: rec, opts: opts, sessions: make(map[*Session]struct{})}
	if !r.Enabled() {
		return r
	}

	r.stop = make(chan struct{})
	r.done = make(chan struct{})
	go r.sampleSessions()

	return r
}

func (r *SessionRecorder) Enabled() bool { return r != nil && r.rec != nil && r.opts.Period > 0 }

func (r *SessionRecorder) NewSession(ctx context.Context, counters stats.Stats) *Session {
	s := &Session{recorder: r, counters: counters, labels: maps.Clone(xctx.LabelsFromContext(ctx))}
	if r.Enabled() {
		s.id = rand.Text()
	}

	return s
}

func (r *SessionRecorder) Close() error {
	if !r.Enabled() {
		return nil
	}

	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		active := len(r.sessions)
		r.mu.Unlock()

		close(r.stop)
		<-r.done

		if active > 0 {
			r.closeErr = fmt.Errorf("session recorder closed with %d active sessions", active)
		}
	})

	return r.closeErr
}

func (r *SessionRecorder) sampleSessions() {
	defer close(r.done)

	ticker := time.NewTicker(r.opts.Period)
	defer ticker.Stop()

	var batch []*Session
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			batch = batch[:0]
			for s := range r.sessions {
				batch = append(batch, s)
			}
			r.mu.Unlock()

			for _, s := range batch {
				_ = s.Interim(context.Background(), now)
			}
		}
	}
}

func (r *SessionRecorder) write(ctx context.Context, record any) error {
	if r.rec == nil {
		return nil
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.opts.WriteTimeout)
	defer cancel()

	return r.rec.Record(ctx, data)
}

func (r *SessionRecorder) track(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.closed {
		r.sessions[s] = struct{}{}
	}
}

func (r *SessionRecorder) untrack(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.sessions, s)
}

func (r *SessionRecorder) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.closed
}
