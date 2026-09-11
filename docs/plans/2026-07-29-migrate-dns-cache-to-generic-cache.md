# Migrate DNS cache to the generic `cache.Cache` module

## Context

GOST has **two** unrelated cache implementations for `[]byte`-style data:

- A **bespoke DNS cache** at `x/internal/util/resolver/cache.go` — a `*resolver.Cache`
  type that stores `*dns.Msg` values, decrements answer TTLs on read, and supports
  serve-stale. It is used only by `x/resolver/resolver.go` (`localResolver.cache`)
  and `x/handler/dns/handler.go` (`dnsHandler.cache`).
- A **generic cache module** (`core/cache.Cache` interface: `Get/Set/Delete` over
  `[]byte`/`*Entry`) with `x/cache` in-memory (`NewMemoryCache`) and Redis
  (`NewRedisCache`) backends, wired through `registry.CacheRegistry()` via
  `x/config/parsing/cache.ParseCache`. It already supports TTL, LRU eviction,
  background cleanup, and named-config backends.

The task: delete the bespoke DNS cache and back the DNS resolver with the
shared generic cache. This removes a duplicate, less-capable implementation and
lets DNS caching inherit the generic module's eviction/cleanup/Redis backends.

The migration is **behavior-preserving**: DNS caching stays in-process and
serve-stale still works, because the generic `Entry.Expiration` model maps cleanly
onto the resolver's `Load() → (msg, remainingTTL)` contract (an expired-but-present
entry is returned with `Expired()==true`, exactly the serve-stale trigger the
resolver/handler already key off).

## Key insight — how to preserve DNS TTL semantics on `[]byte`

`dns.Msg` serializes cleanly via `miekg/dns` (`Pack() ([]byte,error)`,
`(*Msg).Unpack([]byte) error`, present in v1.1.61). The original code, on
**Store**, rewrote every answer record's `Header().Ttl` to the cache TTL, and on
**Load** decremented each by elapsed time — so after Load every answer TTL equals
*remaining* cache life. We reproduce that on read by simply **setting each answer
TTL to `max(1, int(remaining.Seconds()))`** where `remaining = entry.TTL()`. This
matches the old behavior exactly and avoids needing storedAt. (For an expired
entry, `remaining <= 0` → answer TTL clamped to 1, same as before.)

## Plan

### 1. Replace bespoke cache with adapter helpers (delete the `Cache` type)

In `x/internal/util/resolver/` replace `cache.go` with `key.go` keeping
`NewCacheKey`/`CacheKey`, and add the three adapter helpers (in a new small file
`cache_adapter.go`, or append to `key.go`). The helpers take the generic
`cache.Cache` from `github.com/go-gost/core/cache`.

```go
// CacheKey is a DNS-specific cache key string.
type CacheKey = string

func NewCacheKey(q *dns.Question) CacheKey { /* unchanged */ }

const defaultTTL = 60 * time.Second

// LoadMsg returns the cached DNS message and its remaining TTL (<=0 => stale/expired).
// Miss (ErrNotFound) returns (nil, 0).
func LoadMsg(ctx context.Context, c cache.Cache, key CacheKey) (*dns.Msg, time.Duration) {
    ent, err := c.Get(ctx, string(key))
    if err != nil { // includes ErrNotFound
        return nil, 0
    }
    mr := new(dns.Msg)
    if err := mr.Unpack(ent.Data); err != nil {
        return nil, 0
    }
    remaining := ent.TTL()
    for i := range mr.Answer {
        if d := uint32(remaining.Seconds()); d > 0 {
            mr.Answer[i].Header().Ttl = d
        } else {
            mr.Answer[i].Header().Ttl = 1
        }
    }
    return mr, remaining
}

// StoreMsg serializes mr into the cache. ttl<0 => skip (do not cache);
// ttl==0 => use min answer TTL (or defaultTTL); ttl>0 overrides all answer TTLs.
func StoreMsg(ctx context.Context, c cache.Cache, key CacheKey, mr *dns.Msg, ttl time.Duration) {
    if key == "" || mr == nil || ttl < 0 {
        return
    }
    if ttl == 0 {
        ttl = defaultTTL
        for _, a := range mr.Answer {
            if v := time.Duration(a.Header().Ttl) * time.Second; v < ttl {
                ttl = v
            }
        }
    }
    b, err := mr.Pack()
    if err != nil {
        return
    }
    c.Set(ctx, string(key), b, cache.WithTTL(ttl))
}

// RefreshMsgTTL re-stores mr under key, extending its life by ttl (replaces old RefreshTTL).
func RefreshMsgTTL(ctx context.Context, c cache.Cache, key CacheKey, mr *dns.Msg, ttl time.Duration) {
    StoreMsg(ctx, c, key, mr, ttl)
}
```

Delete the old `Cache` struct and `NewCache/WithLogger/WithMaxSize/Load/Store/
RefreshTTL/cleanupLocked` methods from this package.

### 2. Update `x/resolver/resolver.go`

- Field: `cache *resolver_util.Cache` → `cache cache.Cache` (import
  `github.com/go-gost/core/cache` and `xcache "github.com/go-gost/x/cache"`).
- `NewResolver`: replace `resolver_util.NewCache().WithLogger(options.logger)`
  with `xcache.NewMemoryCache(xcache.Options{DefaultTTL: defaultTTL,
  CleanupInterval: time.Minute, Logger: options.logger})`.
- `lookupCache` (resolver.go:246) and `resolveIPs` (resolver.go:294,306):
  `r.cache.Load(...)` → `resolver_util.LoadMsg(r.cache, ...)`;
  `r.cache.Store(...)` → `resolver_util.StoreMsg(r.cache, ...)`. The returned
  `(mr, ttl)` semantics are unchanged (ttl = remaining; `ttl <= 0` is the
  serve-stale/refresh trigger).

### 3. Update `x/handler/dns/handler.go`

- Field (handler.go:45): `cache *resolver_util.Cache` → `cache cache.Cache`.
- Construction (handler.go:74): `resolver_util.NewCache().WithLogger(log)` →
  `xcache.NewMemoryCache(xcache.Options{DefaultTTL: h.md.ttl, CleanupInterval:
  time.Minute, Logger: log})` (store path passes an explicit TTL, so DefaultTTL is
  only a fallback).
- handler.go:320 `h.cache.Load(...)` → `resolver_util.LoadMsg(...)`.
- handler.go:343 `h.cache.RefreshTTL(...)` → `resolver_util.RefreshMsgTTL(ctx,
  h.cache, resolver_util.NewCacheKey(&mq.Question[0]), mr, h.md.ttl)`.
- handler.go:386 `h.cache.Store(...)` → `resolver_util.StoreMsg(...)`.

### 4. Update tests

- `x/resolver/resolver_test.go:81` `resolver_util.NewCache().WithLogger(...)` →
  `xcache.NewMemoryCache(xcache.Options{Logger: xlogger.Nop()})` (import
  `xcache`, drop `resolver_util.NewCache`). Test `TestResolve_AsyncCacheHitWithRefresh`
  at :308 uses `r.cache.Store(ctx, key, mr, -1*time.Second)` → `resolver_util.StoreMsg(r.cache, key, mr, -1*time.Second)` (negative TTL skips, same as before, so the entry won't be cached and async refresh fires — assertion unchanged).
- `x/handler/dns/handler_test.go`: `h.cache = resolver_util.NewCache().WithLogger(...)`
  (lines 905, 1095) → `h.cache = xcache.NewMemoryCache(xcache.Options{Logger: nopLog()})`;
  `h.cache.Store(ctx, key, respMsg, <ttl>)` (lines 786, 934, 1035) →
  `resolver_util.StoreMsg(h.cache, key, respMsg, <ttl>)`. The `TestRequest_CacheHit`
  assertions on `ttl.Seconds() > 0` and stale behavior are preserved by the
  `LoadMsg` normalization.

### 5. Verify

```bash
cd x && go build ./... && go vet ./...
# Tests live in the gost module's e2e; resolver/handler unit tests:
cd x && go test ./resolver/... ./handler/dns/... -race
```

(Per `x/CLAUDE.md`, unit tests are the exception; `go build ./... && go vet ./...`
is the primary gate for this module. Run the resolver/dns package tests only if
they exist locally — they do.)

## Trade-offs / skipped

- **No `CacheRegistry` wiring for DNS** (resolver does not yet pull a named cache
  by name from config). The migration swaps only the backing store; making DNS use
  a user-configured named Redis cache is a separate enhancement. Add when a config
  knob is wanted.
- **No Redis-by-default for DNS** — keeps current in-memory behavior; just now
  backed by the shared, eviction-capable `x/cache` memory backend.
- Helper functions instead of a wrapper type: the generic `cache.Cache` interface
  can't carry DNS-typed methods, so three small package-level adapters keep call
  sites nearly identical and avoid inventing a new type with one impl.
