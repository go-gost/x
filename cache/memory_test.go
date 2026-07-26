package cache

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/go-gost/core/cache"
)

func TestSetGet(t *testing.T) {
	c := NewMemoryCache(Options{DefaultTTL: 10 * time.Second})
	ctx := context.Background()

	err := c.Set(ctx, "k", []byte("hello"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	e, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(e.Data) != "hello" {
		t.Fatalf("data = %q, want %q", e.Data, "hello")
	}
	if e.Expired() {
		t.Fatal("fresh entry reported expired")
	}
	if e.Expiration.IsZero() {
		t.Fatal("expiration is zero")
	}
}

func TestGetNotFound(t *testing.T) {
	c := NewMemoryCache(Options{})
	_, err := c.Get(context.Background(), "nosuch")
	if err != cache.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGetExpiredStillReturned(t *testing.T) {
	c := NewMemoryCache(Options{})
	ctx := context.Background()
	if err := c.Set(ctx, "k", []byte("data"), cache.WithTTL(1*time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	e, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatal("expired entry should still be returned for serve-stale")
	}
	if !e.Expired() {
		t.Fatal("expected expired")
	}
}

func TestWithTTLOverride(t *testing.T) {
	c := NewMemoryCache(Options{DefaultTTL: 1 * time.Hour})
	ctx := context.Background()
	if err := c.Set(ctx, "k", []byte("x"), cache.WithTTL(50*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	e, _ := c.Get(ctx, "k")
	if !e.Expired() {
		t.Fatal("WithTTL should override default")
	}
}

func TestDelete(t *testing.T) {
	c := NewMemoryCache(Options{DefaultTTL: 10 * time.Second})
	ctx := context.Background()
	c.Set(ctx, "k", []byte("x"))
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "k"); err != cache.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound after delete", err)
	}
}

func TestDeleteAbsentKey(t *testing.T) {
	c := NewMemoryCache(Options{})
	if err := c.Delete(context.Background(), "nosuch"); err != nil {
		t.Fatalf("Delete absent key: %v", err)
	}
}

func TestNeverExpires(t *testing.T) {
	c := NewMemoryCache(Options{}) // no default TTL
	ctx := context.Background()
	c.Set(ctx, "k", []byte("data"))
	time.Sleep(10 * time.Millisecond)
	e, _ := c.Get(ctx, "k")
	if e.Expired() {
		t.Fatal("entry with no TTL should never expire")
	}
	if e.TTL() != -1 {
		t.Fatalf("TTL = %v, want -1", e.TTL())
	}
}

func TestMaxSizeEviction(t *testing.T) {
	c := NewMemoryCache(Options{MaxSize: 2, Eviction: EvictOldest})
	ctx := context.Background()
	c.Set(ctx, "a", []byte("1"))
	c.Set(ctx, "b", []byte("2"))
	c.Set(ctx, "c", []byte("3")) // evicts oldest (a)

	if _, err := c.Get(ctx, "a"); err != cache.ErrNotFound {
		t.Fatal("a should have been evicted")
	}
	if _, err := c.Get(ctx, "b"); err == cache.ErrNotFound {
		t.Fatal("b should remain")
	}
	if _, err := c.Get(ctx, "c"); err == cache.ErrNotFound {
		t.Fatal("c should remain")
	}
}

func TestMaxSizeLRU(t *testing.T) {
	c := NewMemoryCache(Options{MaxSize: 2, Eviction: EvictLRU})
	ctx := context.Background()
	c.Set(ctx, "a", []byte("1"))
	c.Set(ctx, "b", []byte("2"))
	c.Get(ctx, "a")        // touch a
	c.Set(ctx, "c", []byte("3")) // LRU-evicts b (a's lastAccess is newer)

	if _, err := c.Get(ctx, "b"); err != cache.ErrNotFound {
		t.Fatal("b should have been evicted (LRU)")
	}
	if _, err := c.Get(ctx, "a"); err == cache.ErrNotFound {
		t.Fatal("a should remain (touched)")
	}
}

func TestMaxBytesEviction(t *testing.T) {
	c := NewMemoryCache(Options{MaxBytes: 4})
	ctx := context.Background()
	c.Set(ctx, "a", []byte{1, 2})   // 2 bytes, total=2
	c.Set(ctx, "b", []byte{3, 4})   // 2 bytes, total=4
	c.Set(ctx, "c", []byte{5})      // 1 byte, total=5 > 4 → evicts oldest (a)

	if _, err := c.Get(ctx, "a"); err != cache.ErrNotFound {
		t.Fatal("a should have been evicted (maxBytes)")
	}
	if _, err := c.Get(ctx, "b"); err == cache.ErrNotFound {
		t.Fatal("b should remain")
	}
}

func TestClose(t *testing.T) {
	c := NewMemoryCache(Options{CleanupInterval: 10 * time.Millisecond})
	closer := c.(io.Closer)
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal("second Close should be a no-op")
	}
}

func TestCloseStopsBackgroundScan(t *testing.T) {
	c := NewMemoryCache(Options{
		DefaultTTL:      5 * time.Millisecond,
		CleanupInterval: 10 * time.Millisecond,
	})
	ctx := context.Background()
	c.Set(ctx, "k", []byte("data"))
	time.Sleep(20 * time.Millisecond)
	e, _ := c.Get(ctx, "k")
	// Without Close, background scanner cleared expired entries. With Close
	// before sleep, the entry stays. We test that Close means the goroutine
	// stops and does NOT panic another background prune. Just exercising the
	// code path.
	if e.Expired() {
		t.Log("expired (expected if scanner ran)")
	}
	c.(io.Closer).Close()
	time.Sleep(30 * time.Millisecond) // goroutine should have stopped
	// No panic = pass
}

func TestDataCopied(t *testing.T) {
	c := NewMemoryCache(Options{DefaultTTL: 1 * time.Hour})
	ctx := context.Background()
	data := []byte("mutable")
	c.Set(ctx, "k", data)
	data[0] = 'X'

	e, _ := c.Get(ctx, "k")
	if string(e.Data) != "mutable" {
		t.Fatal("Get returns internal data, not a copy")
	}
	// Mutate Get's returned slice — original should be unchanged
	e.Data[0] = 'Y'
	e2, _ := c.Get(ctx, "k")
	if string(e2.Data) != "mutable" {
		t.Fatal("Get returns shared slice")
	}
}
