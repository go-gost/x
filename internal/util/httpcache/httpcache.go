// Package httpcache provides an HTTP response cache layer over the generic
// core cache.Cache interface. It is shared by the forwarder and sniffing
// sniffers to cache upstream HTTP responses for reverse-proxy / CDN-mirror
// use cases (see gost issue #349).
//
// The generic cache stores opaque []byte; this package owns all HTTP policy
// (which methods/statuses are cacheable, per-status TTLs, serve-stale, body
// size limits) and the response (de)serialization via net/http.
package httpcache

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-gost/core/cache"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// Policy holds the HTTP caching rules for a service.
type Policy struct {
	// DefaultTTL is the TTL for a cached response whose status has no explicit
	// StatusTTL entry.
	DefaultTTL time.Duration
	// StatusTTL maps an HTTP status code to a TTL, overriding DefaultTTL.
	StatusTTL map[int]time.Duration
	// ServeStale serves an expired cached response when the upstream fetch
	// fails.
	ServeStale bool
	// Methods is the set of cacheable request methods (upper-case). Defaults
	// to GET and HEAD when empty.
	Methods map[string]bool
	// MaxBodyBytes is the maximum serialized response size to cache. Responses
	// exceeding it are not cached. 0 means the DefaultMaxBodyBytes default.
	MaxBodyBytes int
}

// DefaultMaxBodyBytes is the cache size cap applied when Policy.MaxBodyBytes
// is unset.
const DefaultMaxBodyBytes = 1 << 20 // 1MB

// Cache wraps a core cache.Cache with HTTP-specific policy and serialization.
type Cache struct {
	store  cache.Cache
	policy Policy
}

// New creates an HTTP cache over store with the given policy. Returns nil if
// store is nil so callers can treat "no cache" as a nil *Cache.
func New(store cache.Cache, policy Policy) *Cache {
	if store == nil {
		return nil
	}
	if len(policy.Methods) == 0 {
		policy.Methods = map[string]bool{http.MethodGet: true, http.MethodHead: true}
	}
	if policy.MaxBodyBytes <= 0 {
		policy.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return &Cache{store: store, policy: policy}
}

// Metadata keys for HTTP cache policy, read from handler metadata.
const (
	mdKeyTTL          = "cache.ttl"
	mdKeyStatusPrefix = "cache.status." // per-status TTL: cache.status.200 = 60m
	mdKeyServeStale   = "cache.serveStale"
	mdKeyMethods      = "cache.methods" // slice of cacheable methods
	mdKeyMaxBodyBytes = "cache.maxBodyBytes" //
)

// FromMetadata builds an HTTP cache over store, reading its policy from handler
// metadata. Returns nil when store is nil (no cache configured). Shared by all
// handlers that support response caching so the metadata contract stays in one
// place.
func FromMetadata(store cache.Cache, md mdata.Metadata) *Cache {
	if store == nil {
		return nil
	}

	policy := Policy{
		DefaultTTL:   mdutil.GetDuration(md, mdKeyTTL),
		ServeStale:   mdutil.GetBool(md, mdKeyServeStale),
		MaxBodyBytes: mdutil.GetInt(md, mdKeyMaxBodyBytes),
	}

	// ponytail: brute-force 100-599 for cache.status.<code> keys.
	// At most a handful match; 500 fast metadata lookups is fine.
	for code := 100; code < 600; code++ {
		key := mdKeyStatusPrefix + strconv.Itoa(code)
		if v := mdutil.GetString(md, key); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				if policy.StatusTTL == nil {
					policy.StatusTTL = make(map[int]time.Duration)
				}
				policy.StatusTTL[code] = d
			}
		}
	}

	if methods := mdutil.GetStrings(md, mdKeyMethods); len(methods) > 0 {
		policy.Methods = make(map[string]bool, len(methods))
		for _, m := range methods {
			policy.Methods[m] = true
		}
	}

	return New(store, policy)
}

// Key builds the cache key from the request line: "GET example.com/api/users".
func Key(method, host, uri string) string {
	return method + " " + host + " " + uri
}

// CacheableRequest reports whether req's method is eligible for caching.
// Cheap pre-check so callers skip cache work for POST/etc.
func (c *Cache) CacheableRequest(req *http.Request) bool {
	if c == nil || req == nil {
		return false
	}
	return c.policy.Methods[req.Method]
}

// Cacheable reports whether the request/response pair may be stored: an
// eligible method plus a 2xx/3xx status.
func (c *Cache) Cacheable(req *http.Request, resp *http.Response) bool {
	if !c.CacheableRequest(req) {
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// TTLFor returns the TTL to apply for a response with the given status.
func (c *Cache) TTLFor(status int) time.Duration {
	if c == nil {
		return 0
	}
	if ttl, ok := c.policy.StatusTTL[status]; ok {
		return ttl
	}
	return c.policy.DefaultTTL
}

// ServeStale reports whether stale entries may be served on upstream failure.
func (c *Cache) ServeStale() bool {
	if c == nil {
		return false
	}
	return c.policy.ServeStale
}

// MaxBodyBytes returns the configured serialized-response size cap.
func (c *Cache) MaxBodyBytes() int {
	if c == nil {
		return 0
	}
	return c.policy.MaxBodyBytes
}

// Lookup returns the cached response for req, whether it is stale (expired),
// and whether an entry was found. The returned response's Body must be closed
// by the caller. req is passed to http.ReadResponse so HEAD parses body-less.
func (c *Cache) Lookup(ctx context.Context, req *http.Request) (resp *http.Response, stale bool, ok bool) {
	if c == nil {
		return nil, false, false
	}
	e, err := c.store.Get(ctx, Key(req.Method, req.Host, req.RequestURI))
	if err != nil || e == nil {
		return nil, false, false
	}
	resp, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(e.Data)), req)
	if err != nil {
		return nil, false, false
	}
	return resp, e.Expired(), true
}

// Store saves a serialized response (as produced by resp.Write) under req's
// key, using the TTL for status.
func (c *Cache) Store(ctx context.Context, req *http.Request, data []byte, status int) error {
	if c == nil {
		return nil
	}
	return c.store.Set(ctx, Key(req.Method, req.Host, req.RequestURI), data, cache.WithTTL(c.TTLFor(status)))
}

// TeeWriter wraps w so bytes written to it are also captured for caching, up
// to MaxBodyBytes. If the cap is exceeded, capture is abandoned (Captured
// returns nil) so oversized responses aren't cached — the client write is
// unaffected either way.
func (c *Cache) TeeWriter(w io.Writer) *TeeWriter {
	return &TeeWriter{w: w, max: c.policy.MaxBodyBytes}
}

// TeeWriter captures a bounded copy of everything written through it.
type TeeWriter struct {
	w         io.Writer
	buf       bytes.Buffer
	max       int
	truncated bool
}

// Write forwards p to the underlying writer and, unless the cap is exceeded,
// captures it. The client write always happens first and its result is
// returned verbatim.
func (t *TeeWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if !t.truncated && n > 0 {
		if t.buf.Len()+n > t.max {
			t.truncated = true
			t.buf.Reset()
		} else {
			t.buf.Write(p[:n])
		}
	}
	return n, err
}

// Captured returns the captured response bytes, or nil if the cap was
// exceeded (response too large to cache).
func (t *TeeWriter) Captured() []byte {
	if t.truncated {
		return nil
	}
	return t.buf.Bytes()
}
