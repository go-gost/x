# GOST Dashboard Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Filter dashboard chains by the current config and expose resolver cache hit/miss/store counters, so the overview reflects the running configuration and cache effectiveness.

**Architecture:** The collector stores an allowed-chain set; `ObserveChains` drops chains not in the set, and `Apply(cfg)` rebuilds the set from `cfg.Chains`. Resolver cache statistics are atomic counters inside `resolver_util.Cache`, exposed through `localResolver.Stats()` and captured by `WrapResolver` into the existing module counters.

**Tech Stack:** Go (x module), `github.com/go-gost/core/resolver`, `github.com/go-gost/x/internal/util/resolver`, standard `testing`.

**Spec:** `x/docs/superpowers/specs/2026-11-09-gost-dashboard-phase3-design.md`

## Global Constraints

- Do **not** modify `core/`.
- Chain filtering uses only `cfg.Chains`; runtime plugin chains are not included.
- Resolver cache counters are cumulative and atomic; no per-host keys.
- Cache stats are per resolver name; no hostnames or credentials in the snapshot.
- Wrappers forward `io.Closer`.
- Code comments in English only; tests run per package.
- Plans carry per-task Implementation records; commit after each completed task (commit only, never push).

## Review Focus

- **Stale chains:** a chain removed from the config must disappear from the snapshot after `Apply`.
- **Nil/empty config:** `Apply(nil)` and a config with no chains must clear the filter and not panic.
- **Cache hit/miss semantics:** a `Load` that finds an entry counts as a hit even if expired; a `Load` that finds nothing counts as a miss. A/AAAA fallback can produce one miss and one hit for the same hostname.
- **Cache stats concurrency:** `Stats()` must be safe under concurrent `Load`/`Store`.
- **Hot-path allocation:** `WrapResolver` must capture the stats reader once and must not allocate on `Resolve`.

## File Structure

```
x/dashboard/
  collector.go       chainFilter, SetChainFilter, ObserveChains filter, Reset clears
  apply.go           chainNames + SetChainFilter call
  collector_test.go  filter tests
  apply_test.go      Apply filter tests
  module.go          ModuleStats cache fields, moduleCounters cache fields, Flush/Observe
  event.go           ModuleStatsEvent cache fields
  snapshot.go        ModuleStats cache fields
  wrap.go            resolverWrapper.cacheStats capture
  module_test.go     Flush cache stats test
x/internal/util/resolver/
  cache.go           CacheStats, atomic counters, Stats()
  cache_test.go      Stats test
x/resolver/
  resolver.go        localResolver.Stats()
  resolver_test.go   Stats test
```

---

### Task 1: Chain filter by config

**Files:**
- Modify: `x/dashboard/collector.go`
- Modify: `x/dashboard/apply.go`
- Modify: `x/dashboard/collector_test.go`
- Modify: `x/dashboard/apply_test.go`

**Interfaces:**
- Produces:
  - `func (c *Collector) SetChainFilter(names map[string]struct{})`
  - `func chainNames(cfg *config.Config) map[string]struct{}`

- [ ] **Step 1: Write the failing test for filtering**

`x/dashboard/collector_test.go`:

```go
func TestObserveChainsFiltersByAllowedNames(t *testing.T) {
	c := NewCollector()
	c.SetChainFilter(map[string]struct{}{"chain-0": {}})
	c.ObserveChains(map[string]*ChainSnapshot{
		"chain-0":   {Name: "chain-0"},
		"chain-old": {Name: "chain-old"},
	})
	snap := c.Snapshot()
	if _, ok := snap.Chains["chain-0"]; !ok {
		t.Fatal("chain-0 should be present")
	}
	if _, ok := snap.Chains["chain-old"]; ok {
		t.Fatal("chain-old should be filtered out")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./dashboard/ -run TestObserveChainsFiltersByAllowedNames -v`
Expected: FAIL (compile error: `SetChainFilter` undefined)

- [ ] **Step 3: Implement the filter**

In `x/dashboard/collector.go`:
- Add `chainFilter map[string]struct{}` to `Collector`.
- Add `SetChainFilter` (lock, assign).
- In `ObserveChains`, skip names not in `chainFilter` when it is non-nil.
- In `Reset`, set `chainFilter = nil`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./dashboard/ -run TestObserveChainsFiltersByAllowedNames -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for Apply**

`x/dashboard/apply_test.go`:

```go
func TestApplySetsChainFilterFromConfig(t *testing.T) {
	Apply(&config.Config{Chains: []*config.ChainConfig{{Name: "chain-0"}}})
	t.Cleanup(func() { Apply(nil) })

	Default().ObserveChains(map[string]*ChainSnapshot{
		"chain-0":   {Name: "chain-0"},
		"chain-old": {Name: "chain-old"},
	})
	snap := Default().Snapshot()
	if _, ok := snap.Chains["chain-0"]; !ok {
		t.Fatal("chain-0 should be present")
	}
	if _, ok := snap.Chains["chain-old"]; ok {
		t.Fatal("chain-old should be filtered out")
	}

	Apply(&config.Config{})
	Default().ObserveChains(map[string]*ChainSnapshot{
		"chain-old": {Name: "chain-old"},
	})
	snap = Default().Snapshot()
	if _, ok := snap.Chains["chain-old"]; ok {
		t.Fatal("chain-old should disappear after reload with empty config")
	}
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `go test ./dashboard/ -run TestApplySetsChainFilterFromConfig -v`
Expected: FAIL (`chain-old` still present)

- [ ] **Step 7: Implement Apply filter**

In `x/dashboard/apply.go`:
- Add `chainNames(cfg *config.Config) map[string]struct{}` that returns `nil` when `cfg == nil`, and otherwise returns a non-nil map of non-empty `cfg.Chains[].Name` (an empty map filters out every chain).
- In `Apply`, after `ResetState()`, call `Default().SetChainFilter(chainNames(cfg))`.

- [ ] **Step 8: Run the test to verify it passes**

Run: `go test ./dashboard/ -run TestApplySetsChainFilterFromConfig -v`
Expected: PASS

- [ ] **Step 9: Run package tests**

Run: `go test ./dashboard/ -count=1`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add dashboard/collector.go dashboard/apply.go dashboard/collector_test.go dashboard/apply_test.go
git commit -m "feat(dashboard): filter chains by current config"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `6bbdbfd`.
- Files changed: `x/dashboard/collector.go`, `x/dashboard/apply.go`, `x/dashboard/collector_test.go`, `x/dashboard/apply_test.go`.
- Tests/commands and results: `go test ./dashboard/ -run TestObserveChainsFiltersByAllowedNames -v` RED (compile error: `SetChainFilter` undefined) → GREEN; `go test ./dashboard/ -run TestApplySetsChainFilterFromConfig -v` RED (`chain-old should be filtered out`) → GREEN; `go test ./dashboard/ -count=1` PASS.
- Review findings and fixes: none yet (final whole-branch review pending).
- Deferred items/limitations: plugin chains are not in the filter; `Apply(nil)` clears filtering.

---

### Task 2: Resolver cache counters

**Files:**
- Modify: `x/internal/util/resolver/cache.go`
- Create: `x/internal/util/resolver/cache_test.go`
- Modify: `x/resolver/resolver.go`
- Modify: `x/resolver/resolver_test.go`

**Interfaces:**
- Produces:
  - `type CacheStats struct { Hits, Misses, Stores uint64 }` in `internal/util/resolver`
  - `func (c *Cache) Stats() CacheStats`
  - `func (r *localResolver) Stats() resolver_util.CacheStats`

- [ ] **Step 1: Write the failing test for Cache.Stats**

`x/internal/util/resolver/cache_test.go`:

```go
package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheStatsCountsHitsMissesStores(t *testing.T) {
	c := NewCache()
	q := dns.Question{Name: "example.com.", Qclass: dns.ClassINET, Qtype: dns.TypeA}
	key := NewCacheKey(&q)

	// First load is a miss.
	_, _ = c.Load(context.Background(), key)
	st := c.Stats()
	if st.Misses != 1 || st.Hits != 0 || st.Stores != 0 {
		t.Fatalf("after miss = %+v", st)
	}

	// Store a response.
	msg := &dns.Msg{}
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Ttl: 60},
		A:   net.ParseIP("127.0.0.1"),
	})
	c.Store(context.Background(), key, msg, time.Minute)
	st = c.Stats()
	if st.Misses != 1 || st.Hits != 0 || st.Stores != 1 {
		t.Fatalf("after store = %+v", st)
	}

	// Second load is a hit.
	_, _ = c.Load(context.Background(), key)
	st = c.Stats()
	if st.Misses != 1 || st.Hits != 1 || st.Stores != 1 {
		t.Fatalf("after hit = %+v", st)
	}

	// Expired entries still count as hits.
	c.entries[key] = &cacheItem{msg: msg.Copy(), ts: time.Now().Add(-time.Hour), ttl: time.Minute}
	_, _ = c.Load(context.Background(), key)
	st = c.Stats()
	if st.Misses != 1 || st.Hits != 2 || st.Stores != 1 {
		t.Fatalf("after expired hit = %+v", st)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/util/resolver/ -run TestCacheStatsCountsHitsMissesStores -v`
Expected: FAIL (compile error: `CacheStats` undefined)

- [ ] **Step 3: Implement CacheStats and counters**

In `x/internal/util/resolver/cache.go`:
- Add `CacheStats` struct.
- Add `hits, misses, stores atomic.Uint64` to `Cache`.
- Increment `misses` on `Load` miss, `hits` on `Load` hit, `stores` on successful `Store`.
- Add `Stats() CacheStats`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/util/resolver/ -run TestCacheStatsCountsHitsMissesStores -v`
Expected: PASS

- [ ] **Step 5: Write the concurrency test**

`x/internal/util/resolver/cache_test.go` (add `sync` to the import block):

```go
func TestCacheStatsConcurrent(t *testing.T) {
	c := NewCache()
	q := dns.Question{Name: "example.com.", Qclass: dns.ClassINET, Qtype: dns.TypeA}
	key := NewCacheKey(&q)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = c.Load(context.Background(), key)
				c.Store(context.Background(), key, &dns.Msg{}, time.Minute)
			}
		}()
	}
	wg.Wait()
	_ = c.Stats()
}
```

- [ ] **Step 6: Run the concurrency test with -race**

Run: `go test -race ./internal/util/resolver/ -run TestCacheStatsConcurrent -v`
Expected: PASS

- [ ] **Step 7: Write the failing test for localResolver.Stats**

`x/resolver/resolver_test.go`:

```go
func TestLocalResolverStatsExposesCache(t *testing.T) {
	r := &localResolver{cache: resolver_util.NewCache()}
	st := r.Stats()
	if st.Hits != 0 || st.Misses != 0 || st.Stores != 0 {
		t.Fatalf("zero stats = %+v", st)
	}
}
```

- [ ] **Step 8: Run the test to verify it fails**

Run: `go test ./resolver/ -run TestLocalResolverStatsExposesCache -v`
Expected: FAIL (compile error: `Stats` undefined)

- [ ] **Step 9: Implement localResolver.Stats**

In `x/resolver/resolver.go`:

```go
func (r *localResolver) Stats() resolver_util.CacheStats {
	return r.cache.Stats()
}
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `go test ./resolver/ -run TestLocalResolverStatsExposesCache -v`
Expected: PASS

- [ ] **Step 11: Run package tests**

Run: `go test ./internal/util/resolver/ ./resolver/ -count=1`
Expected: PASS

- [ ] **Step 12: Commit**

```bash
git add internal/util/resolver/cache.go internal/util/resolver/cache_test.go resolver/resolver.go resolver/resolver_test.go
git commit -m "feat(resolver): count cache hits, misses, and stores"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `496b761`.
- Files changed: `x/internal/util/resolver/cache.go`, `x/internal/util/resolver/cache_test.go`, `x/resolver/resolver.go`, `x/resolver/resolver_test.go`.
- Tests/commands and results: `go test ./internal/util/resolver/ -run TestCacheStatsCountsHitsMissesStores -v` RED (compile error: `Stats` undefined) → GREEN; `go test -race ./internal/util/resolver/ -run TestCacheStatsConcurrent -v` PASS; `go test ./resolver/ -run TestLocalResolverStatsExposesCache -v` RED (compile error: `Stats` undefined) → GREEN; `go test ./internal/util/resolver/ ./resolver/ -count=1` PASS.
- Review findings and fixes: the plan's cache test used `logger.Default()`, which is nil in a fresh test process and panics in `Cache.Store`; the test uses `xlogger.Nop()` instead. Production always sets a logger via `WithLogger`.
- Deferred items/limitations: counters are process-cumulative; they reset only when a new resolver (and cache) is constructed.

---

### Task 3: Expose cache stats in the dashboard

**Files:**
- Modify: `x/dashboard/module.go`
- Modify: `x/dashboard/event.go`
- Modify: `x/dashboard/snapshot.go`
- Modify: `x/dashboard/wrap.go`
- Modify: `x/dashboard/module_test.go`

**Interfaces:**
- Consumes:
  - `resolver_util.CacheStats`
  - `localResolver.Stats() resolver_util.CacheStats`
- Produces:
  - `ModuleStats.CacheHits`, `CacheMisses`, `CacheStores uint64`
  - `ModuleStatsEvent.CacheHits`, `CacheMisses`, `CacheStores uint64`
  - `resolverWrapper.cacheStats func() resolver_util.CacheStats`

- [ ] **Step 1: Write the failing test**

`x/dashboard/module_test.go` (add `net` and `resolver_util "github.com/go-gost/x/internal/util/resolver"` to the import block):

```go
type fakeResolverWithStats struct {
	resolver.Resolver
	stats resolver_util.CacheStats
}

func (f *fakeResolverWithStats) Resolve(context.Context, string, string, ...resolver.Option) ([]net.IP, error) {
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

func (f *fakeResolverWithStats) Stats() resolver_util.CacheStats { return f.stats }

func TestFlushEmitsResolverCacheStats(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	r := &fakeResolverWithStats{stats: resolver_util.CacheStats{Hits: 3, Misses: 1, Stores: 2}}
	w := WrapResolver("dns", r)
	if _, err := w.Resolve(context.Background(), "ip", "example.com"); err != nil {
		t.Fatal(err)
	}
	Flush()

	m := moduleStats(t, Default().Snapshot(), "resolver", "dns", "")
	if m.CacheHits != 3 || m.CacheMisses != 1 || m.CacheStores != 2 {
		t.Fatalf("cache stats = %+v", m)
	}
}

func TestWrapResolverCapturesStatsOnce(t *testing.T) {
	r := &fakeResolverWithStats{}
	w := WrapResolver("dns", r)
	rw, ok := w.(*resolverWrapper)
	if !ok {
		t.Fatal("WrapResolver did not return *resolverWrapper")
	}
	if rw.cacheStats == nil {
		t.Fatal("cacheStats was not captured")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./dashboard/ -run TestFlushEmitsResolverCacheStats -v`
Expected: FAIL (compile error: `CacheHits` undefined)

- [ ] **Step 3: Add fields to ModuleStats and ModuleStatsEvent**

In `x/dashboard/snapshot.go`:

```go
CacheHits   uint64 `json:"cacheHits"`
CacheMisses uint64 `json:"cacheMisses"`
CacheStores uint64 `json:"cacheStores"`
```

In `x/dashboard/event.go`:

```go
CacheHits   uint64
CacheMisses uint64
CacheStores uint64
```

- [ ] **Step 4: Add counters and wire them through Flush/Observe**

In `x/dashboard/module.go`:
- Add `cacheHits, cacheMisses, cacheStores atomic.Uint64` to `moduleCounters`.
- Include them in `snapshot()`.
- Include them in the `ModuleStatsEvent` in `Flush`.

In `x/dashboard/collector.go`:
- Copy `CacheHits`, `CacheMisses`, `CacheStores` from the event into `ModuleStats` in `Observe`.

- [ ] **Step 5: Capture cache stats in the resolver wrapper**

In `x/dashboard/wrap.go` (add `resolver_util "github.com/go-gost/x/internal/util/resolver"` to the import block):
- Add `cacheStats func() resolver_util.CacheStats` to `resolverWrapper`.
- In `WrapResolver`, type-assert `next` to `interface{ Stats() resolver_util.CacheStats }` and capture the method.
- In `Resolve`, after the call, store the latest stats in the module counters (even on error).

- [ ] **Step 6: Run the test to verify it passes**

Run: `go test ./dashboard/ -run TestFlushEmitsResolverCacheStats -v`
Expected: PASS

- [ ] **Step 7: Run package tests**

Run: `go test ./dashboard/ -count=1`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add dashboard/module.go dashboard/event.go dashboard/snapshot.go dashboard/wrap.go dashboard/module_test.go
git commit -m "feat(dashboard): expose resolver cache stats"
```

**Implementation record:**
- Date/status: _to fill_
- Repo + commit: _to fill_
- Files changed: _to fill_
- Tests/commands and results: _to fill_
- Review findings and fixes: _to fill_
- Deferred items/limitations: _to fill_

---

### Task 4: Final verification and records

**Files:**
- Modify: `x/docs/plans/2026-11-09-gost-dashboard-phase3.md`
- Modify: `.memory/notes/gost-dashboard-port-eval.md`

- [ ] **Step 1: Run the full affected test suite**

Run: `go test ./dashboard/ ./resolver/ ./internal/util/resolver/ ./config/loader/ ./api/ ./chain/ -count=1`
Expected: PASS

- [ ] **Step 2: Run race tests**

Run: `go test -race ./dashboard/ ./resolver/ -count=1`
Expected: PASS

- [ ] **Step 3: Run vet**

Run: `go vet ./dashboard/ ./resolver/ ./internal/util/resolver/`
Expected: clean

- [ ] **Step 4: Build the binary**

Run: `cd gost && go build ./cmd/gost`
Expected: exit 0

- [ ] **Step 5: Fill in the implementation records**

Fill in the "Implementation record" sections for Tasks 1-3 and add a final record for Task 4.

- [ ] **Step 6: Update the memory note**

Add Phase 3 facts to `.memory/notes/gost-dashboard-port-eval.md` and commit in the memory repo:

```bash
cd /root/code/go-gost && git add .memory/notes/gost-dashboard-port-eval.md && git commit -m "docs(memory): record dashboard phase 3"
```

- [ ] **Step 7: Commit**

```bash
git add docs/plans/2026-11-09-gost-dashboard-phase3.md
git commit -m "docs(plans): record dashboard phase 3 implementation"
```

**Implementation record:**
- Date/status: _to fill_
- Repo + commit: _to fill_
- Files changed: _to fill_
- Tests/commands and results: _to fill_
- Review findings and fixes: _to fill_
- Deferred items/limitations: _to fill_
