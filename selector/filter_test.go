package selector

import (
	"context"
	"testing"
	"time"

	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/selector"
	xmd "github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// testMarkable is a test item that implements both Metadatable and Markable.
type testMarkable struct {
	md     metadata.Metadata
	marker selector.Marker
}

func newTestMarkable(md map[string]any) *testMarkable {
	return &testMarkable{
		md:     xmd.NewMetadata(md),
		marker: selector.NewFailMarker(),
	}
}

func (t *testMarkable) Metadata() metadata.Metadata {
	return t.md
}

func (t *testMarkable) Marker() selector.Marker {
	return t.marker
}

// testMetadatable only implements Metadatable, not Markable.
type testMetadatable struct {
	md metadata.Metadata
}

func newTestMetadatable(md map[string]any) *testMetadatable {
	return &testMetadatable{md: xmd.NewMetadata(md)}
}

func (t *testMetadatable) Metadata() metadata.Metadata {
	return t.md
}

// --- FailFilter tests ---

func TestFailFilter_Empty(t *testing.T) {
	f := FailFilter[int](1, time.Second)
	if vs := f.Filter(context.Background()); len(vs) != 0 {
		t.Fatalf("expected empty, got %d items", len(vs))
	}
}

func TestFailFilter_Single(t *testing.T) {
	f := FailFilter[int](1, time.Second)
	vs := f.Filter(context.Background(), 42)
	if len(vs) != 1 || vs[0] != 42 {
		t.Fatalf("expected [42], got %v", vs)
	}
}

func TestFailFilter_HealthyItems(t *testing.T) {
	f := FailFilter[*testMarkable](2, 10*time.Second)

	items := []*testMarkable{
		newTestMarkable(nil),
		newTestMarkable(nil),
	}
	vs := f.Filter(context.Background(), items[0], items[1])
	if len(vs) != 2 {
		t.Fatalf("expected 2 items, got %d", len(vs))
	}
}

func TestFailFilter_DeadItem(t *testing.T) {
	f := FailFilter[*testMarkable](1, 10*time.Second)

	alive := newTestMarkable(nil)
	dead := newTestMarkable(nil)
	dead.Marker().Mark() // count=1, within failTimeout

	vs := f.Filter(context.Background(), alive, dead)
	if len(vs) != 1 || vs[0] != alive {
		t.Fatalf("expected only alive item, got %v", vs)
	}
}

func TestFailFilter_ExpiredFailTimeout(t *testing.T) {
	f := FailFilter[*testMarkable](1, 50*time.Millisecond)

	item := newTestMarkable(nil)
	item.Marker().Mark()

	// Wait for fail timeout to expire
	time.Sleep(80 * time.Millisecond)

	vs := f.Filter(context.Background(), item)
	if len(vs) != 1 {
		t.Fatalf("expected item to be included after timeout, got %d items", len(vs))
	}
}

func TestFailFilter_PerItemOverrides(t *testing.T) {
	f := FailFilter[*testMarkable](1, 10*time.Second)

	// Item with custom maxFails=5
	item := newTestMarkable(map[string]any{
		"maxFails":    5,
		"failTimeout": "1h",
	})
	item.Marker().Mark() // count=1, but maxFails=5 so still alive

	vs := f.Filter(context.Background(), item)
	if len(vs) != 1 {
		t.Fatalf("expected item with high maxFails to pass, got %d items", len(vs))
	}
}

func TestFailFilter_NilMarker(t *testing.T) {
	f := FailFilter[*testMetadatable](1, time.Second)

	item := newTestMetadatable(nil)
	vs := f.Filter(context.Background(), item)
	if len(vs) != 1 {
		t.Fatalf("expected non-markable item to pass, got %d items", len(vs))
	}
}

func TestFailFilter_AllDead(t *testing.T) {
	f := FailFilter[*testMarkable](1, 10*time.Second)

	dead1 := newTestMarkable(nil)
	dead1.Marker().Mark()
	dead2 := newTestMarkable(nil)
	dead2.Marker().Mark()

	vs := f.Filter(context.Background(), dead1, dead2)
	if len(vs) != 0 {
		t.Fatalf("expected all dead items filtered, got %d items", len(vs))
	}
}

func TestFailFilter_ZeroMaxFails(t *testing.T) {
	// Zero maxFails should default to 1, so a single mark should filter the item
	f := FailFilter[*testMarkable](0, 10*time.Second)

	item := newTestMarkable(nil)
	item.Marker().Mark() // count=1, which >= maxFails(defaulted to 1)

	vs := f.Filter(context.Background(), item, newTestMarkable(nil))
	if len(vs) != 1 {
		t.Fatalf("expected zero maxFails to default to 1, got %d items", len(vs))
	}
}

func TestFailFilter_ZeroFailTimeout(t *testing.T) {
	// Zero failTimeout should default to DefaultFailTimeout (10s)
	f := FailFilter[*testMarkable](1, 0)

	item := newTestMarkable(nil)
	item.Marker().Mark() // count=1, within DefaultFailTimeout → dead

	vs := f.Filter(context.Background(), item, newTestMarkable(nil))
	if len(vs) != 1 {
		t.Fatalf("expected zero failTimeout to use default, got %d items", len(vs))
	}
}

// --- BackupFilter tests ---

func TestBackupFilter_Empty(t *testing.T) {
	f := BackupFilter[int]()
	if vs := f.Filter(context.Background()); len(vs) != 0 {
		t.Fatalf("expected empty, got %d items", len(vs))
	}
}

func TestBackupFilter_Single(t *testing.T) {
	f := BackupFilter[int]()
	vs := f.Filter(context.Background(), 42)
	if len(vs) != 1 || vs[0] != 42 {
		t.Fatalf("expected [42], got %v", vs)
	}
}

func TestBackupFilter_PrimaryPreferred(t *testing.T) {
	f := BackupFilter[*testMetadatable]()

	primary := newTestMetadatable(nil)
	backup := newTestMetadatable(map[string]any{"backup": true})

	vs := f.Filter(context.Background(), primary, backup)
	if len(vs) != 1 || vs[0] != primary {
		t.Fatalf("expected only primary, got %v", vs)
	}
}

func TestBackupFilter_AllBackup(t *testing.T) {
	f := BackupFilter[*testMetadatable]()

	b1 := newTestMetadatable(map[string]any{"backup": true})
	b2 := newTestMetadatable(map[string]any{"backup": true})

	vs := f.Filter(context.Background(), b1, b2)
	if len(vs) != 2 {
		t.Fatalf("expected all backups returned when no primaries, got %d items", len(vs))
	}
}

func TestBackupFilter_NoBackup(t *testing.T) {
	f := BackupFilter[*testMetadatable]()

	p1 := newTestMetadatable(nil)
	p2 := newTestMetadatable(nil)

	vs := f.Filter(context.Background(), p1, p2)
	if len(vs) != 2 {
		t.Fatalf("expected all primaries, got %d items", len(vs))
	}
}

func TestBackupFilter_BackupFalse(t *testing.T) {
	f := BackupFilter[*testMetadatable]()

	item := newTestMetadatable(map[string]any{"backup": false})
	vs := f.Filter(context.Background(), item)
	if len(vs) != 1 {
		t.Fatalf("expected item with backup=false to be treated as primary, got %d items", len(vs))
	}
}

// Verify the constants are accessible
func TestFilterConstants(t *testing.T) {
	if DefaultMaxFails != 1 {
		t.Fatalf("DefaultMaxFails expected 1, got %d", DefaultMaxFails)
	}
	if DefaultFailTimeout != 10*time.Second {
		t.Fatalf("DefaultFailTimeout expected 10s, got %v", DefaultFailTimeout)
	}
}

// Verify metadata label constants via mdutil
func TestFilterMetadataLabels(t *testing.T) {
	md := xmd.NewMetadata(map[string]any{
		"weight":      5,
		"backup":      true,
		"maxFails":    3,
		"failTimeout": "30s",
	})

	if w := mdutil.GetInt(md, labelWeight); w != 5 {
		t.Fatalf("weight: expected 5, got %d", w)
	}
	if !mdutil.GetBool(md, labelBackup) {
		t.Fatal("backup: expected true")
	}
	if mf := mdutil.GetInt(md, labelMaxFails); mf != 3 {
		t.Fatalf("maxFails: expected 3, got %d", mf)
	}
	if ft := mdutil.GetDuration(md, labelFailTimeout); ft != 30*time.Second {
		t.Fatalf("failTimeout: expected 30s, got %v", ft)
	}
}
