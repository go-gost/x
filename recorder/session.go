package recorder

import (
	"cmp"
	"context"
	"sync"
	"time"

	"github.com/go-gost/core/observer/stats"
)

type Session struct {
	recorder *SessionRecorder
	counters stats.Stats
	labels   map[string]string
	id       string

	mu       sync.Mutex
	base     HandlerRecorderObject
	cursor   cursor
	finished bool
}

func sessionMetadata(base HandlerRecorderObject, labels map[string]string) HandlerRecorderObject {
	base.HTTP, base.TLS, base.DNS, base.Websocket, base.Redis = nil, nil, nil, nil, nil
	if base.Labels == nil {
		base.Labels = labels
	}

	return base
}

func (s *Session) Start(base HandlerRecorderObject) {
	if s == nil || s.recorder == nil || !s.recorder.Enabled() {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return
	}

	base = sessionMetadata(base, s.labels)
	if base.RecordMode == "off" {
		return
	}

	if !s.cursor.started() {
		s.cursor.open(cmp.Or(base.Time, time.Now()))
		s.recorder.track(s)
	}

	base.Time = s.cursor.startedAt
	s.base = base
}

func (s *Session) Finish(ctx context.Context, final HandlerRecorderObject) error {
	if s == nil || s.recorder == nil {
		return nil
	}
	r := s.recorder

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return nil
	}
	s.finished = true

	r.untrack(s)

	if final.Time.IsZero() || final.RecordMode == "off" {
		return nil
	}
	if final.Labels == nil {
		final.Labels = s.labels
	}

	if !r.Enabled() {
		return r.write(ctx, final)
	}
	if r.isClosed() {
		return ErrSessionRecorderClosed
	}
	if !s.cursor.started() {
		s.cursor.open(final.Time)
	}

	return s.emit(ctx, final, time.Now(), PhaseFinal)
}

func (s *Session) Interim(ctx context.Context, now time.Time) error {
	if s == nil || s.recorder == nil || !s.recorder.Enabled() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.counters == nil || !now.After(s.cursor.last) {
		return nil
	}
	if s.base.RecordMode == "off" {
		return nil
	}

	ro := s.base
	ro.InputBytes = s.counters.Get(stats.KindInputBytes)
	ro.OutputBytes = s.counters.Get(stats.KindOutputBytes)
	if s.cursor.idle(ro) {
		return nil
	}

	return s.emit(ctx, ro, now, PhaseInterim)
}

func (s *Session) emit(ctx context.Context, ro HandlerRecorderObject, now time.Time, phase string) error {
	record := s.cursor.record(ro, now, phase, s.id)
	if err := s.recorder.write(ctx, record); err != nil {
		return err
	}
	s.cursor.commit(record)

	return nil
}
