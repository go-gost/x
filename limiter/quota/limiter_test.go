package quota

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestLimiter(t *testing.T, opts Options) *Limiter {
	t.Helper()
	l := NewLimiter("test", opts)
	t.Cleanup(func() { l.Close() })
	return l
}

func TestLimiterBlocksAtLimit(t *testing.T) {
	l := newTestLimiter(t, Options{Limit: 100})

	l.AddIn(60)
	if l.Blocked() {
		t.Fatalf("should not block at 60/100")
	}
	l.AddOut(40)
	if !l.Blocked() {
		t.Fatalf("should block at 100/100")
	}
	if s := l.Snapshot(); !s.Blocked || s.Used != 100 {
		t.Fatalf("snapshot=%+v, want blocked used=100", s)
	}
}

func TestLimiterUnblockOnOverwrite(t *testing.T) {
	l := newTestLimiter(t, Options{Limit: 100})
	l.AddIn(150)
	if !l.Blocked() {
		t.Fatalf("expected blocked")
	}

	zero := uint64(0)
	l.Update(Update{Used: &zero})

	if l.Blocked() {
		t.Fatalf("expected unblocked after reset")
	}
	if got := l.Snapshot().Used; got != 0 {
		t.Fatalf("used=%d, want 0", got)
	}
}

func TestLimiterDirection(t *testing.T) {
	l := newTestLimiter(t, Options{Limit: 100, Direction: DirectionIn})

	l.AddOut(500)
	if u := l.Snapshot().Used; u != 0 {
		t.Fatalf("outbound counted under DirectionIn: used=%d", u)
	}
	l.AddIn(100)
	if !l.Blocked() {
		t.Fatalf("expected blocked after inbound reaches limit")
	}
}

func TestLimiterWindowNotStarted(t *testing.T) {
	l := newTestLimiter(t, Options{Limit: 100, StartsAt: time.Now().Add(time.Hour)})

	l.AddIn(500)
	s := l.Snapshot()
	if s.Used != 0 {
		t.Fatalf("counted before startsAt: used=%d", s.Used)
	}
	if s.Active {
		t.Fatalf("should be inactive before startsAt")
	}
	if l.Blocked() {
		t.Fatalf("should not block before startsAt")
	}
}

func TestLimiterFailOpenAfterExpiry(t *testing.T) {
	l := newTestLimiter(t, Options{Limit: 100, ExpiresAt: time.Now().Add(-time.Hour)})

	l.AddIn(500)
	s := l.Snapshot()
	if s.Used != 0 {
		t.Fatalf("counted after expiry: used=%d", s.Used)
	}
	if !s.Expired {
		t.Fatalf("snapshot should report expired")
	}
	if l.Blocked() {
		t.Fatalf("should be fail-open (unblocked) after expiry")
	}
}

func TestLimiterPersistsToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	store := NewFileStore(path)

	l := NewLimiter("svc", Options{Limit: 1000, Store: store})
	l.AddIn(300)
	l.AddOut(200)
	l.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store file: %v", err)
	}
	var data map[string]Record
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec := data["svc"]; rec.Used != 500 {
		t.Fatalf("persisted used=%d, want 500", rec.Used)
	}
}

func TestLimiterRestoresFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	if err := os.WriteFile(path, []byte(`{"svc":{"used":777,"limit":1000}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore(path)
	l := NewLimiter("svc", Options{Limit: 1000, Store: store})
	t.Cleanup(func() { l.Close() })

	if got := l.Snapshot().Used; got != 777 {
		t.Fatalf("restored used=%d, want 777", got)
	}
}

func TestWaitChanNotifiesOnReset(t *testing.T) {
	l := newTestLimiter(t, Options{Limit: 100})
	l.AddIn(200)
	if !l.Blocked() {
		t.Fatal("expected blocked")
	}

	ch := l.WaitChan()
	zero := uint64(0)
	l.Update(Update{Used: &zero})

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("WaitChan not notified after reset")
	}
	if l.Blocked() {
		t.Fatal("expected unblocked after reset")
	}
}

func TestClosedLimiterIsInert(t *testing.T) {
	l := NewLimiter("c", Options{Limit: 100})
	l.AddIn(200)
	if !l.Blocked() {
		t.Fatal("expected blocked")
	}

	ch := l.WaitChan()
	l.Close()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("WaitChan not notified on close")
	}
	if l.Blocked() {
		t.Fatal("closed limiter must be inert (not blocking)")
	}
	l.AddIn(1000)
	if u := l.Snapshot().Used; u != 200 {
		t.Fatalf("closed limiter counted: used=%d, want 200", u)
	}
}

func TestLimiterResetsOnWindowChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	store := NewFileStore(path)

	t1 := time.Now().Add(time.Hour)
	l1 := NewLimiter("svc", Options{Limit: 1000, ExpiresAt: t1, Store: store})
	l1.AddIn(500)
	l1.Close()

	t2 := time.Now().Add(2 * time.Hour)
	l2 := NewLimiter("svc", Options{Limit: 1000, ExpiresAt: t2, Store: store})
	t.Cleanup(func() { l2.Close() })

	if u := l2.Snapshot().Used; u != 0 {
		t.Fatalf("counter not reset on window change: used=%d, want 0", u)
	}
}
