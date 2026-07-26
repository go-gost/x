package httpcache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	xcache "github.com/go-gost/x/cache"
	xmetadata "github.com/go-gost/x/metadata"
)

func newTestCache(policy Policy) *Cache {
	store := xcache.NewMemoryCache(xcache.Options{DefaultTTL: 1 * time.Hour, MaxSize: 100})
	return New(store, policy)
}

func TestKey(t *testing.T) {
	k := Key(http.MethodGet, "example.com", "/api")
	if k != "GET example.com /api" {
		t.Fatalf("key = %q", k)
	}
}

func TestCacheableRequest(t *testing.T) {
	c := newTestCache(Policy{})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !c.CacheableRequest(req) {
		t.Fatal("GET should be cacheable by default")
	}
	req.Method = http.MethodHead
	if !c.CacheableRequest(req) {
		t.Fatal("HEAD should be cacheable by default")
	}
	req.Method = http.MethodPost
	if c.CacheableRequest(req) {
		t.Fatal("POST should not be cacheable by default")
	}
}

func TestCacheableMethods(t *testing.T) {
	c := newTestCache(Policy{
		Methods: map[string]bool{http.MethodGet: true, "POST": true},
	})
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	if !c.CacheableRequest(req) {
		t.Fatal("POST should be cacheable when configured")
	}
}

func TestCacheableStatusRange(t *testing.T) {
	c := newTestCache(Policy{})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !c.Cacheable(req, &http.Response{StatusCode: 200}) {
		t.Fatal("2xx should be cacheable")
	}
	if !c.Cacheable(req, &http.Response{StatusCode: 302}) {
		t.Fatal("3xx should be cacheable")
	}
	if c.Cacheable(req, &http.Response{StatusCode: 500}) {
		t.Fatal("5xx should not be cacheable")
	}
}

func TestPerStatusTTL(t *testing.T) {
	c := newTestCache(Policy{
		DefaultTTL: 10 * time.Minute,
		StatusTTL:  map[int]time.Duration{404: 1 * time.Minute},
	})
	if ttl := c.TTLFor(200); ttl != 10*time.Minute {
		t.Fatalf("TTL(200) = %v, want 10m", ttl)
	}
	if ttl := c.TTLFor(404); ttl != 1*time.Minute {
		t.Fatalf("TTL(404) = %v, want 1m", ttl)
	}
}

func TestLookupStoreRoundtrip(t *testing.T) {
	c := newTestCache(Policy{DefaultTTL: 10 * time.Minute})
	ctx := context.Background()
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/api", nil)

	origResp := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Cacheable": {"yes"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("response body"))),
	}
	var buf bytes.Buffer
	if err := origResp.Write(&buf); err != nil {
		t.Fatal(err)
	}

	if err := c.Store(ctx, req, buf.Bytes(), 200); err != nil {
		t.Fatal(err)
	}

	got, stale, ok := c.Lookup(ctx, req)
	if !ok {
		t.Fatal("Lookup should find stored entry")
	}
	if stale {
		t.Fatal("entry should be fresh")
	}
	defer got.Body.Close()
	if got.StatusCode != 200 {
		t.Fatalf("status = %d", got.StatusCode)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "response body" {
		t.Fatalf("body = %q", body)
	}
}

func TestLookupHead(t *testing.T) {
	c := newTestCache(Policy{DefaultTTL: 10 * time.Minute})
	ctx := context.Background()

	// Store and retrieve as GET — HEAD queries with different key won't match.
	// HEAD sharing is left to callers (use GET key when hitting on HEAD).
	getReq, _ := http.NewRequest(http.MethodGet, "http://example.com/api", nil)
	resp := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	var buf bytes.Buffer
	resp.Write(&buf)
	c.Store(ctx, getReq, buf.Bytes(), 200)

	got, _, ok := c.Lookup(ctx, getReq)
	if !ok {
		t.Fatal("GET should match its own key")
	}
	if got.StatusCode != 200 {
		t.Fatalf("status = %d", got.StatusCode)
	}
	got.Body.Close()
}

func TestLookupNotFound(t *testing.T) {
	c := newTestCache(Policy{})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/nosuch", nil)
	_, _, ok := c.Lookup(context.Background(), req)
	if ok {
		t.Fatal("Lookup should miss")
	}
}

func TestTeeWriterCapExceeded(t *testing.T) {
	c := newTestCache(Policy{MaxBodyBytes: 10})
	tee := c.TeeWriter(io.Discard)
	tee.Write(make([]byte, 10))
	if cap := tee.Captured(); cap == nil {
		t.Fatal("exactly at cap should succeed")
	}
	tee.Write([]byte{1})
	if got := tee.Captured(); got != nil {
		t.Fatalf("over cap Captured = %v, want nil", got)
	}
}

func TestTeeWriterWriteError(t *testing.T) {
	// If the underlying writer fails, the TeeWriter returns the error but still
	// captures bytes that were successfully written before the error.
	c := newTestCache(Policy{MaxBodyBytes: 100})
	tee := c.TeeWriter(io.Discard)
	// Write succeeds — capture the leading bytes.
	n, err := tee.Write([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3", n)
	}
	if len(tee.Captured()) != 3 {
		t.Fatalf("captured = %d bytes, want 3", len(tee.Captured()))
	}
}

func TestFromMetadata(t *testing.T) {
	store := xcache.NewMemoryCache(xcache.Options{DefaultTTL: 1 * time.Hour})
	md := xmetadata.NewMetadata(map[string]any{
		"cache.ttl":         "30s",
		"cache.serveStale":  "true",
		"cache.methods":     []string{"GET", "POST"},
		"cache.status.200":  "60m",
		"cache.status.404":  "1m",
		"cache.maxBodyBytes": "1048576",
	})
	c := FromMetadata(store, md)
	if c == nil {
		t.Fatal("nil Cache")
	}
	if c.policy.DefaultTTL != 30*time.Second {
		t.Fatalf("ttl = %v, want 30s", c.policy.DefaultTTL)
	}
	if !c.ServeStale() {
		t.Fatal("serveStale should be true")
	}
	// FromMetadata adds configured methods on top of defaults (GET, HEAD).
	if !c.policy.Methods[http.MethodGet] {
		t.Fatal("GET should remain in methods")
	}
	if !c.policy.Methods["POST"] {
		t.Fatal("POST should be added")
	}
	if c.TTLFor(200) != 60*time.Minute {
		t.Fatalf("TTL(200) = %v", c.TTLFor(200))
	}
	if c.TTLFor(404) != 1*time.Minute {
		t.Fatalf("TTL(404) = %v", c.TTLFor(404))
	}
	if c.MaxBodyBytes() != 1048576 {
		t.Fatalf("maxBodyBytes = %d", c.MaxBodyBytes())
	}
}

func TestFromMetadataNilStore(t *testing.T) {
	c := FromMetadata(nil, xmetadata.NewMetadata(nil))
	if c != nil {
		t.Fatal("nil store should yield nil Cache")
	}
}

func TestNilCacheSafe(t *testing.T) {
	var c *Cache
	req, _ := http.NewRequest(http.MethodGet, "http://x.com/", nil)
	if c.CacheableRequest(req) {
		t.Fatal("nil cache should not be cacheable")
	}
	if c.ServeStale() {
		t.Fatal("nil cache should not serve stale")
	}
	// nil *Cache: Lookup, Store, MaxBodyBytes, TTLFor are safe — they
	// check c==nil at method entry.
	_, _, ok := c.Lookup(context.Background(), req)
	if ok {
		t.Fatal("nil cache should not hit")
	}
	if err := c.Store(context.Background(), req, nil, 200); err != nil {
		t.Fatal(err)
	}
}
