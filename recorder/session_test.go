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

type flakySink struct {
	sessionSink
	fail     int32
	attempts *atomic.Int32
}

func (s *flakySink) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	if s.attempts.Add(1) <= s.fail {
		return errors.New("sink is down")
	}
	return s.sessionSink.Record(ctx, b, opts...)
}

func TestSessionRecorderEmitsDeltasAndFinalRemainder(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})
	defer r.Close()

	if !r.Enabled() {
		t.Fatal("recorder should be enabled with a period")
	}

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	start := time.Now()
	session.Start(HandlerRecorderObject{Service: "test", Time: start})

	counters.Add(stats.KindOutputBytes, 10)
	waitFor(t, func() bool { return sink.len() > 0 }, "no record while the session ran")

	counters.Add(stats.KindOutputBytes, 7)
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: start, OutputBytes: 17,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	waitFor(t, func() bool { return sink.len() >= 2 }, "no final record")

	raw := sink.snapshot()
	var total uint64
	stream := decodeSessionRecord(t, raw[0]).SessionID
	for i, b := range raw {
		rec := decodeSessionRecord(t, b)
		total += rec.OutputBytesDelta
		if rec.SessionID != stream {
			t.Errorf("record %d: sessionID = %q, want %q", i, rec.SessionID, stream)
		}
		if rec.RecordIndex != uint64(i+1) {
			t.Errorf("record %d: recordIndex = %d", i, rec.RecordIndex)
		}
	}
	if got := decodeSessionRecord(t, raw[len(raw)-1]); got.Phase != PhaseFinal || got.OutputBytes != 17 {
		t.Errorf("last record = %+v, want the final 17", got)
	}
	// Deltas, so the records add up to the traffic instead of restating it.
	if total != 17 {
		t.Errorf("summed deltas = %d, want 17", total)
	}
}

func TestSessionFinishWithoutStart(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})
	defer r.Close()

	session := r.NewSession(context.Background(), nil)
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Time: time.Now(), Err: "dial failed", InputBytes: 3,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}

	raw := sink.snapshot()
	if len(raw) != 1 {
		t.Fatalf("records = %d, want 1", len(raw))
	}
	if rec := decodeSessionRecord(t, raw[0]); rec.Phase != PhaseFinal || rec.InputBytes != 3 {
		t.Errorf("record = %+v, want a final with 3 bytes", rec)
	}
}

// With the period off the whole session is written when it ends, in the shape
// the recorder used before sessions existed.
func TestSessionRecorderDisabledKeepsLegacyRecord(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{})
	defer r.Close()

	if r.Enabled() {
		t.Fatal("recorder should be disabled without a period")
	}

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	session.Start(HandlerRecorderObject{Service: "test", Time: time.Now()})
	counters.Add(stats.KindOutputBytes, 21)

	time.Sleep(50 * time.Millisecond)
	if n := sink.len(); n != 0 {
		t.Fatalf("a disabled recorder wrote %d records mid-session", n)
	}

	stamp := time.Now()
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: stamp, OutputBytes: 21,
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
	if legacy["time"] != stamp.Format(time.RFC3339Nano) {
		t.Errorf("time = %v, want the stamp its handler gave it", legacy["time"])
	}
}

// A handler that zeroes the time of a recorder object means "do not write this":
// handleProxy does it to the outer object of a proxy connection, whose bytes its
// per-request objects carry.
func TestSessionRecorderDisabledDropsUnstampedObjects(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{})
	defer r.Close()

	session := r.NewSession(context.Background(), xstats.NewStats(false))
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", OutputBytes: 137,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if n := sink.len(); n != 0 {
		t.Fatalf("an object its handler never stamped was recorded %d time(s)", n)
	}
}

// "off" is the client's opt-out, and Record enforces it. Periodic reporting must
// not write around it: not the start record, not the final one.
func TestSessionRecorderHonoursRecordModeOff(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})
	defer r.Close()

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	session.Start(HandlerRecorderObject{
		Service: "test", Time: time.Now(), RecordMode: "off",
	})
	counters.Add(stats.KindOutputBytes, 21)

	time.Sleep(MinPeriod + 500*time.Millisecond)
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: time.Now(), RecordMode: "off", OutputBytes: 21,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}

	if n := sink.len(); n != 0 {
		t.Fatalf("a session recorded %d time(s) with recording off", n)
	}
}

// A sink that refuses a record must not cost the traffic it refused: the bytes
// stay in the delta and go out with the next one.
func TestSessionRecorderRefusedIntervalKeepsItsBytes(t *testing.T) {
	var attempts atomic.Int32
	sink := &flakySink{fail: 2, attempts: &attempts}
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})
	defer r.Close()

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	start := time.Now()
	session.Start(HandlerRecorderObject{Service: "test", Time: start})
	counters.Add(stats.KindOutputBytes, 10)

	waitFor(t, func() bool { return attempts.Load() >= 2 }, "the sink was never tried again")
	counters.Add(stats.KindOutputBytes, 7)

	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: start, OutputBytes: 17,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}

	var total uint64
	for _, b := range sink.snapshot() {
		total += decodeSessionRecord(t, b).OutputBytesDelta
	}
	if total != 17 {
		t.Errorf("summed deltas = %d, want 17: a refused record took its bytes with it", total)
	}
}

// The final record is written inline, so its handler learns what happened to it.
func TestSessionRecorderFinishReportsTheSinkError(t *testing.T) {
	var attempts atomic.Int32
	sink := &flakySink{fail: 100, attempts: &attempts}
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})
	defer r.Close()

	session := r.NewSession(context.Background(), xstats.NewStats(false))
	err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: time.Now(), OutputBytes: 21,
	})
	if err == nil {
		t.Fatal("a refused final record must reach the handler as an error")
	}
	if n := sink.len(); n != 0 {
		t.Fatalf("sink took %d records, want none", n)
	}
}

// A sink that stopped answering costs the handler its write timeout, and no more.
func TestSessionRecorderFinishIsBoundedByWriteTimeout(t *testing.T) {
	sink := newGatedSink()
	r := NewSessionRecorder(sink, SessionRecorderOptions{
		Period: MinPeriod, WriteTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(sink.resume)
	defer r.Close()

	session := r.NewSession(context.Background(), xstats.NewStats(false))
	done := make(chan error, 1)
	go func() {
		done <- session.Finish(context.Background(), HandlerRecorderObject{
			Service: "test", Time: time.Now(), OutputBytes: 21,
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("an unresponsive sink must not look like a successful write")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Finish blocked on an unresponsive sink")
	}
}

// Close stops the sampling, says which sessions were still running, and refuses
// the ones that finish afterwards.
func TestSessionRecorderCloseStopsSampling(t *testing.T) {
	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})

	counters := xstats.NewStats(false)
	session := r.NewSession(context.Background(), counters)
	session.Start(HandlerRecorderObject{Service: "test", Time: time.Now()})
	counters.Add(stats.KindOutputBytes, 5)
	waitFor(t, func() bool { return sink.len() > 0 }, "no interim record")

	if err := r.Close(); err == nil {
		t.Error("Close must report the sessions still running")
	}

	counters.Add(stats.KindOutputBytes, 16)
	time.Sleep(2 * MinPeriod)
	if n := sink.len(); n != 1 {
		t.Errorf("records = %d, want 1: the recorder kept sampling after Close", n)
	}

	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: time.Now(), OutputBytes: 21,
	}); !errors.Is(err, ErrSessionRecorderClosed) {
		t.Errorf("finish after Close = %v, want %v", err, ErrSessionRecorderClosed)
	}
}

// A handler whose service configures no recorder still runs: every session is a
// no-op, and nothing dereferences the missing sink.
func TestSessionRecorderWithoutASink(t *testing.T) {
	r := NewSessionRecorder(nil, SessionRecorderOptions{Period: MinPeriod})
	if r.Enabled() {
		t.Fatal("a recorder with no sink cannot be enabled")
	}

	session := r.NewSession(context.Background(), xstats.NewStats(false))
	session.Start(HandlerRecorderObject{Service: "test", Time: time.Now()})
	if err := session.Finish(context.Background(), HandlerRecorderObject{
		Service: "test", Time: time.Now(), OutputBytes: 21,
	}); err != nil {
		t.Errorf("finish: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// Traffic keeps moving while the recorder samples and the session finishes, so
// the records must still add up to exactly what crossed the connection.
func TestSessionRecorderAccountsConcurrentTraffic(t *testing.T) {
	const sessions = 8

	sink := new(sessionSink)
	r := NewSessionRecorder(sink, SessionRecorderOptions{Period: MinPeriod})
	deadline := time.Now().Add(MinPeriod + 300*time.Millisecond)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		written uint64
		failed  []error
	)
	for range sessions {
		wg.Go(func() {
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
		})
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if len(failed) > 0 {
		t.Fatalf("finish failed: %v", failed)
	}

	var total uint64
	seen := map[string]uint64{}
	for _, raw := range sink.snapshot() {
		rec := decodeSessionRecord(t, raw)
		total += rec.InputBytesDelta
		seen[rec.SessionID]++
	}
	if total != written {
		t.Errorf("summed deltas = %d, want %d: concurrent reporting lost or duplicated traffic", total, written)
	}
	if len(seen) != sessions {
		t.Errorf("sessions reported = %d, want %d", len(seen), sessions)
	}
}
