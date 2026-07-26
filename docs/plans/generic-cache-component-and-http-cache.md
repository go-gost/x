# Generic Cache Component + HTTP Response Cache (issue #349)

## Context

Issue [#349](https://github.com/go-gost/gost/issues/349) requests an HTTP response cache so GOST can mirror static sites / CDNs (e.g. gh-pages) via its proxy. GOST currently re-forwards every request to upstream — no caching.

Rather than a one-off HTTP cache, we build a **generic cache component** (interface + memory backend + registry/config wiring), then make the HTTP proxy its first consumer. This is justified — not speculative — because two more consumers are committed roadmap:
- **DNS** ([resolver/cache.go](../../internal/util/resolver/cache.go)) already stores `[]byte`-serializable data with near-identical TTL + serve-stale + async-refresh semantics → migratable to the new interface later.
- **Redis / other backends** are planned beyond in-memory.

Scope decisions carried from prior review rounds:
- Interface trimmed to **3 methods** (`Get`/`Set`/`Delete`). 349's 7-method draft dropped `Has`/`Clear`/`Len` (awkward/expensive on Redis); `RefreshTTL` also dropped — its only consumer is DNS async-refresh ([handler.go:343](../../handler/dns/handler.go#L343)), which is not in this PR, and it is expressible as `Get`+`Set(WithTTL)`. Add it in the DNS-migration PR where it has a real caller and a native Redis `EXPIRE` mapping. The HTTP consumer uses `singleflight`, not `RefreshTTL`, for anti-stampede.
- **HTTP consumer lands in this same PR** as the validating consumer (349 had put it in "Phase 4" — wrong; it's the issue's actual ask). DNS migration and Redis backend are explicit follow-ups, not this PR.
- **Named shared store** referenced by name (`services[].cache: <name>`), not the per-chain-node config from the earlier `http-response-cache-for-reverse-proxy.md` draft (which was per-node, ambiguous with a shared store, and modified `core/chain/node.go`).
- Interface lives in **`core/cache/`** (first-class component, consistent with recorder/limiter — maintainer-approved core addition). HTTP policy configured via **handler metadata**, keeping the generic cache as dumb bytes.

## Architecture

```
caches: (named, registry) ──► registry.CacheRegistry().Get(name) ──► handler.CacheOption
                                                                          │
services[].cache: cache-0                                                 ▼
handler metadata: cache.ttl / cache.status.* / cache.serveStale ─► httpcache.Cache{Store, Policy, sf}
                                                                          │ held by SnifferBuilder (built once in Init)
                                                                          ▼ Build() copies ref per connection (shared store)
                              HandleHTTP ──(before dial)── cache hit? ──► serve from cache
                                          └─(miss)── singleflight ─► dial+roundtrip ─► tee response ─► Store
```

**Key correctness points** (from round-1 review of the sniffer):
- The `Sniffer` is built **per connection** (`SnifferBuilder.Build()`), so the cache/singleflight must live on the **shared** `SnifferBuilder` (built once in `Init`), never on `*Sniffer`. The store itself is a registry singleton, so all handlers/connections referencing the same name share it.
- Cache **hit check goes in `HandleHTTP` before `h.dial`** (and before keep-alive reuse), not inside `httpRoundTrip` — otherwise the upstream dial is already paid and nothing is saved.
- **SNI caching only works with MITM TLS termination.** Non-MITM `HandleTLS` pipes ciphertext ([sniffer_tls.go:116](../../internal/util/sniffing/sniffer_tls.go#L116)) and cannot cache. With `Certificate`+`PrivateKey` set, `terminateTLS` → `HandleHTTP`, so the HTTP cache glue covers SNI-with-MITM automatically — no extra code, just document the requirement.

## Files

### New — the generic component

**`core/cache/cache.go`** (~60 lines) — interface only. First-class component (maintainer-approved core addition). Mirrors `core/recorder/recorder.go` complexity.
```go
package cache

var ErrNotFound = errors.New("cache: key not found")

type Entry struct {
    Data       []byte
    Expiration time.Time // zero = never expires
}
func (e *Entry) Expired() bool
func (e *Entry) TTL() time.Duration // remaining; <=0 expired, -1 never

type SetOptions struct{ TTL time.Duration }
type SetOption func(*SetOptions)
func WithTTL(d time.Duration) SetOption

// Cache is a concurrency-safe []byte KV store. Get returns ErrNotFound ONLY
// when the key is absent; expired entries are returned (with Expired()==true)
// to support serve-stale. Callers serialize/deserialize their own types.
type Cache interface {
    Get(ctx context.Context, key string) (*Entry, error)
    Set(ctx context.Context, key string, data []byte, opts ...SetOption) error
    Delete(ctx context.Context, key string) error
}
```
Three methods only. `Get`/`Set` are load-bearing for HTTP; `Delete` is kept as a fundamental KV primitive (needed for a future PURGE API, unambiguous on every backend). `RefreshTTL` deliberately omitted — see scope decisions above.

**`core/handler/option.go`** (+~6 lines) — add `Cache cache.Cache` field + `func CacheOption(c cache.Cache) Option`, exactly like `RecordersOption` (option.go:40,115).

**`x/cache/memory.go`** (~180 lines) — memory backend implementing `cache.Cache`. Self-contained (no external lib), supersedes the trivial [x/internal/util/cache](../../internal/util/cache/cache.go) and the intent of patrickmn/go-cache. Features: `sync.RWMutex`, per-entry TTL (default from config, `WithTTL` override), `maxSize` + `maxBytes` bounds, eviction `oldest|lru`, optional background cleanup goroutine (stopped via `io.Closer` — registry's `Unregister` calls Close, see [registry.go Unregister](../../registry/registry.go)). No `init()` self-registration (recorder-style; instances are registered by the loader under their config name).

**`x/config/parsing/cache/parse.go`** (~40 lines) — `ParseCache(cfg *config.CacheConfig) cache.Cache`, dispatches on backend field. Only `Memory` now; `Redis`/`File`/`Plugin` are follow-ups (do NOT ship un-parseable empty backend structs). Mirrors [ParseRecorder](../../config/parsing/recorder/parse.go).

**`x/registry/cache.go`** (~40 lines) — `cacheRegistry` embedding `registry[cache.Cache]` + hot-reload `cacheWrapper` delegating each method to the current instance. Copy [x/registry/recorder.go](../../registry/recorder.go) exactly.

**`x/internal/util/httpcache/httpcache.go`** (~150 lines) — HTTP-specific glue over `cache.Cache`, shared by both sniffer packages. Holds all HTTP policy so the generic cache stays dumb bytes:
```go
type Policy struct {
    DefaultTTL   time.Duration
    StatusTTL    map[int]time.Duration // per-status (200/302→60m, 404→1m)
    ServeStale   bool
    Methods      map[string]bool       // default GET, HEAD
    MaxBodyBytes int
}
type Cache struct {
    Store  cache.Cache
    Policy Policy
    sf     singleflight.Group // shared thundering-herd guard
}
func Key(method, host, uri string) string          // "GET example.com/api"
func (c *Cache) Lookup(req) (resp *http.Response, stale bool, ok bool)
func (c *Cache) Cacheable(req, resp) bool           // method + 2xx/3xx + configured statuses
func (c *Cache) TTLFor(status int) time.Duration
func (c *Cache) TeeWriter(w io.Writer) *teeWriter   // captures up to MaxBodyBytes, discards if exceeded
func (c *Cache) Store(req, data []byte, ttl)
```
Serialization uses stdlib `resp.Write` / `http.ReadResponse` (pass the request method so HEAD parses body-less).

### Modified — config & wiring (copy recorder pattern verbatim)

- **`x/config/config.go`** — add `CacheConfig{Name, Memory *MemoryCache}` + `MemoryCache{TTL, MaxSize, MaxBytes, CleanupInterval, Eviction}`; `Config.Caches []*CacheConfig`; `ServiceConfig.Cache string` (name ref, like `Limiter string` at config.go:514).
- **`x/registry/registry.go`** — add `cacheReg` singleton (registry.go:49 style) + `CacheRegistry()` accessor (registry.go:187).
- **`x/config/loader/loader.go`** — add a `registerGroup` block iterating `cfg.Caches` → `ParseCache` → `CacheRegistry()` (copy recorder block loader.go:239-247).
- **`x/config/parsing/service/parse.go`** — look up `registry.CacheRegistry().Get(cfg.Cache)`, read HTTP cache policy from handler metadata, build `httpcache.Cache`, inject via `handler.CacheOption(...)` (alongside `RecordersOption`, parse.go:393). New metadata keys in [parsing/parse.go](../../config/parsing/parse.go): `cache.ttl`, `cache.status.<code>` (via `mdutil.GetStringMapString(md,"cache.status")`), `cache.serveStale`, `cache.methods`, `cache.maxBodyBytes`.

### Modified — HTTP consumers (the feature)

Both sniffer packages get the same edit. `SnifferBuilder` gains a `Cache *httpcache.Cache` field, `Build()` copies it onto `Sniffer`:
- **`x/internal/util/forwarder/`** (`sniffer.go`, `sniffer_http.go`) — serves forward/local + forward/remote.
- **`x/internal/util/sniffing/`** (`sniffer.go`, `sniffer_http.go`) — serves sni + http/connect (+ redirect).

In each `HandleHTTP`: **before `h.dial`** (and before keep-alive reuse at the re-dial branch), if `Cache != nil` and method is cacheable, `Lookup`; on fresh hit write to client (`resp.Write(rw)`), record, and continue the keep-alive loop with correct `shouldClose` (do **not** close the client conn). In `httpRoundTrip`: on miss, run dial+roundtrip inside `sf.Do(key,...)`; if `Cacheable`, wrap `rw` with `TeeWriter` so `resp.Write(tee)` captures bytes, then `Store` after a successful write. On upstream error with a stale entry and `ServeStale`, write the stale response instead of erroring.

The four dispatch sites that call `Build()` are unchanged in shape — they already build a fresh sniffer per connection; the cache reference rides along on the builder:
[forward/local/sniffing.go:79](../../handler/forward/local/sniffing.go#L79), [forward/remote/sniffing.go:79](../../handler/forward/remote/sniffing.go#L79), [sni/sniffing.go:104](../../handler/sni/sniffing.go#L104), [http/connect.go:126](../../handler/http/connect.go#L126). Each handler's `SnifferBuilder` is populated from `h.options.Cache` in `Init`.

## What is NOT in this PR (deferred, interface already accommodates)

- Redis / File / Plugin backends (Redis struct + impl land together in a follow-up).
- DNS / router / limiter / TLS-certpool migration to the new interface (Phase 2+).
- PURGE API, Vary, RFC 7234 conditional requests, disk persistence.

## Verification

```bash
cd x   && go build ./... && go vet ./...
cd ../gost && go build ./cmd/gost/...
cd ../core && go build ./... && go vet ./...   # interface + handler option
```

Unit tests:
- `x/cache/memory_test.go` — set/get/expire, `WithTTL` override, oldest & lru eviction, maxBytes bound, cleanup goroutine stop on Close, `Get` returns expired entry (serve-stale contract). Run with `CGO_ENABLED=1 go test -race`.
- `x/internal/util/httpcache/httpcache_test.go` — key format, per-status TTL, `Cacheable` (method/status matrix), teeWriter cutoff at `MaxBodyBytes`, response round-trip via `resp.Write`/`http.ReadResponse` incl. HEAD.

End-to-end (memory backend, HTTP proxy):
```yaml
caches:
- name: c0
  memory: { maxSize: 1000, maxBytes: 268435456, eviction: lru }
services:
- name: web
  addr: ":8080"
  handler:
    type: http
    metadata: { cache: c0, cache.ttl: 60m, cache.status.404: 1m, cache.serveStale: true }
  forwarder:
    nodes: [{ name: up, addr: "backend:80" }]
```
Two identical GETs: first logs `<-> upstream`, second serves from cache (no upstream dial in trace). Kill the backend after warming the cache → with `serveStale: true`, the stale entry is still served.
```bash
cd gost && go run ./cmd/gost/... -C cache.yml -D   # -D trace shows hit/miss/dial
```
For SNI: same works only when the service also has MITM certs configured (otherwise TLS is piped and uncacheable — documented behavior).
