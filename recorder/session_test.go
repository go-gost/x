package recorder

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xstats "github.com/go-gost/x/observer/stats"
)

// sessionSink collects what the reporter delivers.
type sessionSink struct {
	mu      sync.Mutex
	records [][]byte
}

func (s *sessionSink) Record(_ context.Context, b []byte, _ ...recorder.RecordOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, append([]byte(nil), b...))
	return nil
}

func (s *sessionSink) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.records...)
}

func (s *sessionSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// gatedSink holds every delivery until it is released: a recorder backend that
// has stopped answering looks like this from the reporter's side.
type gatedSink struct {
	sessionSink
	entered  chan struct{}
	release  chan struct{}
	arrived  sync.Once
	released sync.Once
}

func newGatedSink() *gatedSink {
	return &gatedSink{entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *gatedSink) resume() { s.released.Do(func() { close(s.release) }) }

func (s *gatedSink) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	s.arrived.Do(func() { close(s.entered) })
	select {
	case <-s.release:
		return s.sessionSink.Record(ctx, b, opts...)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func decodeSessionRecord(t *testing.T, b []byte) SessionRecord {
	t.Helper()
	var r SessionRecord
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	return r
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

func TestSessionRecorderEmitsDeltasAndFinalRemainder(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, ReporterOptions{Period: MinPeriod})
	defer r.Close()

	if !r.Enabled() {
		t.Fatal("reporter should be enabled with a positive period")
	}

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	session.Start(HandlerRecorderObject{Service: "test", Time: time.Now()})

	counters.Add(stats.KindOutputBytes, 10)
	waitFor(t, func() bool { return sink.len() > 0 }, "no record while the session was running")

	counters.Add(stats.KindOutputBytes, 7)
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: time.Now(), OutputBytes: 17,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	waitFor(t, func() bool { return sink.len() >= 2 }, "no final record")

	raw := sink.snapshot()
	var total uint64
	stream := decodeSessionRecord(t, raw[0]).SessionID
	if got := decodeSessionRecord(t, raw[0]); got.Phase != PhaseStart || got.RecordIndex != 1 || got.InputBytes != 0 || got.OutputBytes != 0 {
		t.Fatalf("unexpected start record: %+v", got)
	}
	for i, b := range raw {
		rec := decodeSessionRecord(t, b)
		total += rec.OutputBytes

		if rec.SessionID != stream {
			t.Errorf("record %d: session = %s, want %s", i, rec.SessionID, stream)
		}
		if rec.RecordIndex != uint64(i+1) {
			t.Errorf("record %d: record index = %d, want %d", i, rec.RecordIndex, i+1)
		}
		if i == 0 {
			continue
		}
		want := PhaseInterim
		if i == len(raw)-1 {
			want = PhaseFinal
		}
		if rec.Phase != want {
			t.Errorf("record %d: phase = %s, want %s", i, rec.Phase, want)
		}
	}
	// Deltas: the records add up to the traffic instead of restating it.
	if total != 17 {
		t.Errorf("reported bytes = %d, want 17", total)
	}
}

// A session that ends before it starts still reports once: a handler that fails
// before it has anything to route.
func TestSessionFinishWithoutStart(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, ReporterOptions{Period: MinPeriod})
	defer r.Close()

	session := r.NewSession(context.Background(), nil)
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Time: time.Now(), Err: "dial failed", InputBytes: 3,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	waitFor(t, func() bool { return sink.len() == 1 }, "no record for an unstarted session")

	rec := decodeSessionRecord(t, sink.snapshot()[0])
	if rec.Phase != PhaseFinal || rec.InputBytes != 3 {
		t.Errorf("unexpected record: %+v", rec)
	}
}

// Without a period the session writes the whole thing inline when it ends,
// exactly as a handler did before the reporter existed.
func TestSessionRecorderDisabledKeepsLegacyRecord(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, ReporterOptions{})
	defer r.Close()

	if r.Enabled() {
		t.Fatal("reporter should be disabled without a period")
	}

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	session.Start(HandlerRecorderObject{Service: "test", Time: time.Now()})
	counters.Add(stats.KindOutputBytes, 21)

	time.Sleep(50 * time.Millisecond)
	if n := sink.len(); n != 0 {
		t.Fatalf("a disabled reporter wrote %d records mid-session", n)
	}

	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: time.Now(), OutputBytes: 21,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}

	raw := sink.snapshot()
	if len(raw) != 1 {
		t.Fatalf("records = %d, want 1", len(raw))
	}
	var legacy map[string]any
	if err := json.Unmarshal(raw[0], &legacy); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := legacy["phase"]; ok {
		t.Error("the legacy record must keep its shape")
	}
	if legacy["outputBytes"] != float64(21) {
		t.Errorf("outputBytes = %v, want 21", legacy["outputBytes"])
	}
}

func TestSessionRecorderStartIsEmittedOnce(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, ReporterOptions{Period: MinPeriod})
	defer r.Close()

	s := r.NewSession(context.Background(), nil)
	s.Start(HandlerRecorderObject{Service: "test", Time: time.Now()})
	s.Start(HandlerRecorderObject{Service: "test", Time: time.Now().Add(time.Second)})
	if err := s.Finish(context.Background(), HandlerRecorderObject{Service: "test", Time: time.Now(), InputBytes: 4}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	waitFor(t, func() bool { return len(sink.snapshot()) == 2 }, "short session did not produce start and final")
	raw := sink.snapshot()
	if got := decodeSessionRecord(t, raw[0]); got.Phase != PhaseStart || got.RecordIndex != 1 {
		t.Fatalf("unexpected start: %+v", got)
	}
	if got := decodeSessionRecord(t, raw[1]); got.Phase != PhaseFinal || got.RecordIndex != 2 || got.InputBytes != 4 {
		t.Fatalf("unexpected final: %+v", got)
	}
}

type flakySink struct {
	sessionSink
	fail     int32
	attempts atomic.Int32
}

func (s *flakySink) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	if s.attempts.Add(1) <= s.fail {
		return errors.New("sink is down")
	}
	return s.sessionSink.Record(ctx, b, opts...)
}

// A sink that fails and recovers must not cost the traffic it failed on, and
// must not be paid twice for it either.
func TestSessionRecorderRetriesTheSameRecord(t *testing.T) {
	sink := &flakySink{fail: 3}
	r := NewSessionRecorder(sink, ReporterOptions{Period: MinPeriod, RetryInterval: time.Millisecond})
	defer r.Close()

	session := r.NewSession(context.Background(), nil)
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Time: time.Now(), InputBytes: 99,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	waitFor(t, func() bool { return sink.len() == 1 }, "the record was never delivered")

	if got := sink.attempts.Load(); got != 4 {
		t.Errorf("attempts = %d, want 4", got)
	}
	rec := decodeSessionRecord(t, sink.snapshot()[0])
	if rec.InputBytes != 99 || rec.RecordIndex != 1 {
		t.Errorf("a retry must repeat the record, not advance the stream: %+v", rec)
	}
}

// A slow sink costs latency, not records: a finished session waits for room in
// the queue instead of dropping its remainder.
func TestSessionFinishWaitsForQueueCapacity(t *testing.T) {
	sink := newGatedSink()
	r := NewSessionRecorder(sink, ReporterOptions{
		Period: MinPeriod, QueueSize: 1, WriteTimeout: 5 * time.Second, RetryInterval: time.Millisecond,
	})
	defer func() { sink.resume(); r.Close() }()

	// A cancelled context is the normal case: shutdown cancels the connection
	// before the handler defer that finishes the session runs.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	finish := func(n uint64) error {
		return r.NewSession(ctx, nil).Finish(ctx, HandlerRecorderObject{Time: time.Now(), OutputBytes: n})
	}

	if err := finish(10); err != nil {
		t.Fatalf("finish: %v", err)
	}
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("the sender never started")
	}
	if err := finish(20); err != nil { // fills the one slot
		t.Fatalf("finish: %v", err)
	}

	third := make(chan error, 1)
	go func() { third <- finish(30) }()
	select {
	case err := <-third:
		t.Fatalf("a full queue dropped a final record instead of waiting: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	sink.resume()
	select {
	case err := <-third:
		if err != nil {
			t.Fatalf("finish after recovery: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("finalization did not resume")
	}

	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw := sink.snapshot()
	if len(raw) != 3 {
		t.Fatalf("records = %d, want 3", len(raw))
	}
	for i, b := range raw {
		if got := decodeSessionRecord(t, b).OutputBytes; got != uint64((i+1)*10) {
			t.Errorf("record %d: outputBytes = %d, want %d", i, got, (i+1)*10)
		}
	}
}

// A sink that never recovers must not take the handler with it: finalization
// gives up after WriteTimeout, and Close after DrainTimeout.
func TestSessionRecorderGivesUpOnAStalledSink(t *testing.T) {
	sink := newGatedSink()
	r := NewSessionRecorder(sink, ReporterOptions{
		Period: MinPeriod, QueueSize: 1, WriteTimeout: 50 * time.Millisecond,
		RetryInterval: time.Millisecond, DrainTimeout: 200 * time.Millisecond,
	})
	defer sink.resume()

	finish := func(n uint64) error {
		return r.NewSession(context.Background(), nil).
			Finish(context.Background(), HandlerRecorderObject{Time: time.Now(), OutputBytes: n})
	}

	if err := finish(10); err != nil {
		t.Fatalf("finish: %v", err)
	}
	<-sink.entered
	if err := finish(20); err != nil {
		t.Fatalf("finish: %v", err)
	}

	dropped := make(chan error, 1)
	go func() { dropped <- finish(30) }()
	select {
	case err := <-dropped:
		if err == nil {
			t.Error("a stalled sink must not silently accept a record")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("finalization blocked on a stalled sink")
	}

	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		if err == nil {
			t.Error("an abandoned queue must be reported, not hidden")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on a stalled sink")
	}
}

func TestSessionRecorderCloseWaitsForRecovery(t *testing.T) {
	sink := newGatedSink()
	r := NewSessionRecorder(sink, ReporterOptions{
		Period: MinPeriod, WriteTimeout: 10 * time.Millisecond, RetryInterval: time.Millisecond,
	})
	defer func() { sink.resume(); r.Close() }()

	session := r.NewSession(context.Background(), nil)
	if err := session.Finish(context.Background(), HandlerRecorderObject{Time: time.Now(), InputBytes: 42}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	<-sink.entered

	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("the drain abandoned a pending record: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	sink.resume()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the drain never completed")
	}
	if sink.len() != 1 {
		t.Errorf("records = %d, want 1", sink.len())
	}

	after := r.NewSession(context.Background(), nil)
	if err := after.Finish(context.Background(), HandlerRecorderObject{Time: time.Now()}); !errors.Is(err, ErrReporterClosed) {
		t.Errorf("finish after close = %v, want %v", err, ErrReporterClosed)
	}
}

// Traffic keeps moving while the collector samples and the session finishes, so
// the records must still add up to exactly what crossed the connection.
func TestSessionRecorderAccountsConcurrentTraffic(t *testing.T) {
	const sessions = 8

	sink := new(sessionSink)
	r := NewSessionRecorder(sink, ReporterOptions{Period: MinPeriod})

	// Long enough for the collector to sample mid-flight, so interim and final
	// records are produced for the same session concurrently.
	deadline := time.Now().Add(MinPeriod + 300*time.Millisecond)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		written uint64
		failed  []error
	)
	for range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()

			counters := xstats.NewStats(false)
			session := r.NewSession(context.Background(), counters)
			session.Start(HandlerRecorderObject{Time: time.Now()})

			var sent uint64
			for time.Now().Before(deadline) {
				counters.Add(stats.KindInputBytes, 1)
				sent++
				time.Sleep(time.Millisecond)
			}
			err := session.Finish(context.Background(), HandlerRecorderObject{
				Time: time.Now(), InputBytes: counters.Get(stats.KindInputBytes),
			})

			mu.Lock()
			defer mu.Unlock()
			written += sent
			if err != nil {
				failed = append(failed, err)
			}
		}()
	}
	wg.Wait()

	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(failed) != 0 {
		t.Fatalf("finish errors: %v", failed)
	}

	var total uint64
	streams := map[string]int{}
	for _, raw := range sink.snapshot() {
		rec := decodeSessionRecord(t, raw)
		total += rec.InputBytes
		streams[rec.SessionID]++
	}
	if total != written {
		t.Errorf("reported %d bytes, want %d: concurrent reporting lost or duplicated traffic", total, written)
	}
	if len(streams) != sessions {
		t.Errorf("streams = %d, want %d", len(streams), sessions)
	}
	for stream, count := range streams {
		if count < 2 {
			t.Errorf("stream %s was never reported while it ran", stream)
		}
	}
}
