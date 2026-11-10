# GOST Dashboard Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Filter the chain `Gather()` to only the two chain metric families and expose aggregate conn/rate/traffic limiter counters per limiter name.

**Architecture:** `xmetrics.GatherFamilies` builds a temporary Prometheus registry with only the requested collectors. Limiter implementations own a shared `*stats.Stats`; per-key limiters increment atomic counters gated by a package-level `stats.Enable` switch. Dashboard wrappers attach a `Stats()` reader and sample it at `Flush` time, avoiding per-key wrappers and per-request allocations.

**Tech Stack:** Go (x module), `github.com/prometheus/client_golang`, `github.com/go-gost/core/limiter/{conn,rate,traffic}`, standard `testing`.

**Spec:** `x/docs/superpowers/specs/2026-11-09-gost-dashboard-phase4-design.md`

## Global Constraints

- Do **not** modify `core/`.
- `GatherFamilies` returns only the requested families; unknown and duplicate names are ignored.
- Limiter counters are aggregate per limiter name; never per client key.
- `Calls` counts `Allow` invocations across all per-key limiters in a group, so a connection matching multiple rules counts multiple calls; `WaitCalls` behaves the same for traffic groups.
- Limiter increments are gated by `stats.Enabled()`; no locks and no per-request wrapper allocations.
- The limiter stats pointer is created in the limiter constructor before the reload goroutine, avoiding the traffic reload race.
- Quota limiters, frontend work, and release tagging/pushing are out of scope.
- Wrappers forward `io.Closer`.
- Code comments in English only; tests run per package.
- Plans carry per-task Implementation records; commit after each completed task (commit only, never push).

## Review Focus

- **Gather scope:** unrequested families must never appear; duplicate names must not panic.
- **Disabled overhead:** with `stats.Enable(false)`, limiter `Allow`/`Wait` must do only a cheap atomic load.
- **Counter semantics:** conn/rate count calls, allowed, denied; traffic counts wait calls, requested bytes, granted bytes, and denied waits.
- **Traffic reload race:** stats are created before `NewTrafficLimiter` starts its reload goroutine.
- **Sample callback race:** the limiter sample function must be published atomically before the reporter can read it.
- **Wrapper lifetime:** `Close` must reach the inner limiter.

## File Structure

```
x/metrics/
  gather.go          GatherFamilies
  gather_test.go     requested/duplicate tests
x/limiter/stats/
  stats.go           Stats, Snapshot, Enable/IsEnabled
  stats_test.go      counters and disabled behavior
x/limiter/conn/
  limiter.go, conn.go, generator.go, conn_test.go
x/limiter/rate/
  limiter.go, rate.go, generator.go, rate_test.go
x/limiter/traffic/
  limiter.go, traffic.go, generator.go, traffic_test.go
x/dashboard/
  limiter.go         WrapConnLimiter/WrapRateLimiter/WrapTrafficLimiter
  limiter_test.go    wrapper/snapshot integration
  module.go          sample callback + limiter stats emission
  event.go           ModuleStatsEvent.Limiter
  snapshot.go        ModuleStats.Limiter, LimiterStats
  collector.go       Observe copies Limiter
  apply.go           stats.Enable(on)
x/config/loader/
  loader.go          wrap the three limiter registrations
x/api/
  config_limiter.go         wrap traffic limiter at Register
  config_conn_limiter.go    wrap conn limiter at Register
  config_rate_limiter.go    wrap rate limiter at Register
```

---

### Task 1: Family-filtered Gather

**Files:**
- Create: `x/metrics/gather.go`
- Create: `x/metrics/gather_test.go`
- Modify: `x/dashboard/chains.go`

**Interfaces:**
- Produces: `func GatherFamilies(names ...metrics.MetricName) ([]*dto.MetricFamily, error)`

- [ ] **Step 1: Write the failing test**

`x/metrics/gather_test.go`:

```go
package metrics

import (
	"testing"

	"github.com/go-gost/core/metrics"
)

func TestGatherFamiliesOnlyRequested(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	GetCounter(MetricChainErrorsCounter, metrics.Labels{"chain": "gather-test", "node": "node-0"}).Inc()
	GetCounter(MetricServiceRequestsCounter, metrics.Labels{"service": "gather-test", "client": "c"}).Inc()

	mfs, err := GatherFamilies(MetricChainErrorsCounter)
	if err != nil {
		t.Fatal(err)
	}
	if len(mfs) != 1 || mfs[0].GetName() != string(MetricChainErrorsCounter) {
		t.Fatalf("families = %v", mfs)
	}
}

func TestGatherFamiliesDeduplicates(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	if _, err := GatherFamilies(MetricChainErrorsCounter, MetricChainErrorsCounter); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./metrics/ -run 'TestGatherFamilies' -v`
Expected: FAIL (compile error: `GatherFamilies` undefined)

- [ ] **Step 3: Implement GatherFamilies**

In `x/metrics/gather.go`, create a temporary `prometheus.Registry`, dedupe names, register the matching `counter`/`histogram`/`gauge` from the `promMetrics` maps, and return `reg.Gather()`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./metrics/ -run 'TestGatherFamilies' -v`
Expected: PASS

- [ ] **Step 5: Wire the dashboard chain gatherer**

In `x/dashboard/chains.go`, change the default `chainGatherer` to:

```go
if !xmetrics.IsEnabled() {
	return nil, nil
}
return xmetrics.GatherFamilies(
	xmetrics.MetricChainErrorsCounter,
	xmetrics.MetricNodeConnectDurationObserver,
)
```

- [ ] **Step 6: Run the dashboard chain tests**

Run: `go test ./dashboard/ -run TestCollectChainStats -v`
Expected: PASS (the real-registry test now exercises `GatherFamilies`)

- [ ] **Step 7: Commit**

```bash
git add metrics/gather.go metrics/gather_test.go dashboard/chains.go
git commit -m "perf(metrics): gather only the requested families"
```

**Implementation record:**
- Date/status: _to fill_
- Repo + commit: _to fill_
- Files changed: _to fill_
- Tests/commands and results: _to fill_
- Review findings and fixes: _to fill_
- Deferred items/limitations: _to fill_

---

### Task 2: Limiter stats core

**Files:**
- Create: `x/limiter/stats/stats.go`
- Create: `x/limiter/stats/stats_test.go`
- Modify: `x/limiter/conn/limiter.go`, `conn.go`, `generator.go`, `conn_test.go`
- Modify: `x/limiter/rate/limiter.go`, `rate.go`, `generator.go`, `rate_test.go`
- Modify: `x/limiter/traffic/limiter.go`, `traffic.go`, `generator.go`, `traffic_test.go`

**Interfaces:**
- Produces:
  - `type Snapshot struct { Calls, Allowed, Denied, WaitCalls, Requested, Granted uint64 }`
  - `type Stats struct { ... atomics ... }`
  - `func (s *Stats) Call()`, `Allow()`, `Deny()`, `Wait(n int)`, `Grant(n int)`, `Snapshot() Snapshot`
  - `func Enable(bool)`, `func IsEnabled() bool`
  - `func (l *connLimiter) Stats() stats.Snapshot` (same for rate/traffic)

- [ ] **Step 1: Write the failing stats test**

`x/limiter/stats/stats_test.go`:

```go
package stats

import "testing"

func TestStatsGatedByEnable(t *testing.T) {
	Enable(false)
	s := &Stats{}
	s.Call()
	s.Allow()
	if got := s.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("disabled stats = %+v", got)
	}

	Enable(true)
	defer Enable(false)
	s.Call()
	s.Allow()
	s.Deny()
	s.Wait(10)
	s.Grant(7)
	got := s.Snapshot()
	if got.Calls != 1 || got.Allowed != 1 || got.Denied != 1 || got.WaitCalls != 1 || got.Requested != 10 || got.Granted != 7 {
		t.Fatalf("stats = %+v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./limiter/stats/ -run TestStatsGatedByEnable -v`
Expected: FAIL (package/type undefined)

- [ ] **Step 3: Implement the stats package**

`Stats` holds `atomic.Uint64` fields; every increment method checks `IsEnabled()` and the nil receiver; `Snapshot()` loads all fields (nil-safe).

- [ ] **Step 4: Run the stats test**

Run: `go test ./limiter/stats/ -run TestStatsGatedByEnable -v`
Expected: PASS

- [ ] **Step 5: Write failing limiter counter tests**

`x/limiter/conn/conn_test.go` (use the existing `newTestConnLimiter` helper; add `stats: &stats.Stats{}` to that helper):

```go
func TestConnLimiterStats(t *testing.T) {
	stats.Enable(true)
	defer stats.Enable(false)

	l := newTestConnLimiter("$$ 1")
	entry := l.Limiter("1.2.3.4")
	if !entry.Allow(1) {
		t.Fatal("first allow should succeed")
	}
	if entry.Allow(1) {
		t.Fatal("second allow should be denied")
	}
	entry.Allow(-1)

	got := l.Stats()
	if got.Calls != 2 || got.Allowed != 1 || got.Denied != 1 {
		t.Fatalf("stats = %+v", got)
	}
}
```

Add analogous tests:
- `x/limiter/rate/rate_test.go`: `TestRateLimiterStats` with `newTestRateLimiter("$$ 0.1")` (burst 1), two `Allow(1)` calls; assert `Calls=2, Allowed=1, Denied=1`.
- `x/limiter/traffic/traffic_test.go`: `TestTrafficLimiterStats` with `newTestTrafficLimiter("$$ 100B")`; `In(context.Background(), "1.2.3.4:1234").Wait(context.Background(), 100)`; assert `WaitCalls=1, Requested=100, Granted=100`.
- Add `stats: &stats.Stats{}` to the existing `newTestRateLimiter` and `newTestTrafficLimiter` helpers too.

- [ ] **Step 6: Run the limiter tests to verify they fail**

Run: `go test ./limiter/conn/ ./limiter/rate/ ./limiter/traffic/ -run 'Test.*LimiterStats' -v`
Expected: FAIL (`Stats` undefined on the limiter types)

- [ ] **Step 7: Implement the limiter instrumentation**

- Add a `stats *stats.Stats` field to each per-key limiter (`llimiter` / `rlimiter`) and each factory (`connLimiter`, `rateLimiter`, `trafficLimiter`).
- In each factory constructor, create `st := &stats.Stats{}` before starting the reload goroutine.
- Pass `st` to per-key limiters via internal constructors (`newLimiter`, `newLimitGenerator`, etc.); keep the existing exported constructors working by passing `nil`.
- In `Allow`/`Wait`: call `l.stats.Call()` for positive attempts; `Allow`/`Deny` the outcome; traffic uses `Wait(n)`/`Grant(n)` and `Deny()` on `WaitN` error.
- Add `Stats() stats.Snapshot` to each factory.
- Do not change the public `NewLimiter` signatures; add internal constructors with a stats parameter.

- [ ] **Step 8: Run the limiter tests**

Run: `go test ./limiter/conn/ ./limiter/rate/ ./limiter/traffic/ -run 'Test.*LimiterStats|TestNewLimiter' -v`
Expected: PASS

- [ ] **Step 9: Run package tests and race**

Run: `go test ./limiter/conn/ ./limiter/rate/ ./limiter/traffic/ -count=1`
Run: `go test -race ./limiter/conn/ ./limiter/rate/ ./limiter/traffic/ -count=1`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add limiter/stats limiter/conn limiter/rate limiter/traffic
git commit -m "feat(limiter): add aggregate stats counters"
```

**Implementation record:**
- Date/status: _to fill_
- Repo + commit: _to fill_
- Files changed: _to fill_
- Tests/commands and results: _to fill_
- Review findings and fixes: _to fill_
- Deferred items/limitations: _to fill_

---

### Task 3: Dashboard limiter wrappers and exposure

**Files:**
- Create: `x/dashboard/limiter.go`
- Create: `x/dashboard/limiter_test.go`
- Modify: `x/dashboard/module.go`
- Modify: `x/dashboard/event.go`
- Modify: `x/dashboard/snapshot.go`
- Modify: `x/dashboard/collector.go`
- Modify: `x/dashboard/apply.go`
- Modify: `x/config/loader/loader.go`
- Modify: `x/api/config_limiter.go`, `x/api/config_conn_limiter.go`, `x/api/config_rate_limiter.go`

**Interfaces:**
- Consumes:
  - `limiterstats.Snapshot`
  - `connLimiter.Stats()`, `rateLimiter.Stats()`, `trafficLimiter.Stats()`
- Produces:
  - `func WrapConnLimiter(name string, next conn.ConnLimiter) conn.ConnLimiter`
  - `func WrapRateLimiter(name string, next rate.RateLimiter) rate.RateLimiter`
  - `func WrapTrafficLimiter(name string, next traffic.TrafficLimiter) traffic.TrafficLimiter`
  - `type LimiterStats struct { Calls, Allowed, Denied, WaitCalls, Requested, Granted uint64 }`
  - `ModuleStats.Limiter *LimiterStats`
  - `ModuleStatsEvent.Limiter *LimiterStats`

- [ ] **Step 1: Write the failing wrapper test**

`x/dashboard/limiter_test.go`:

```go
func TestWrapConnLimiterExposesStats(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)
	limiterstats.Enable(true)
	defer limiterstats.Enable(false)

	lim := conn.NewConnLimiter(conn.LimitsOption("$$ 1"))
	w := WrapConnLimiter("conn-1", lim)
	entry := w.Limiter("1.2.3.4")
	if !entry.Allow(1) {
		t.Fatal("first allow should succeed")
	}
	if entry.Allow(1) {
		t.Fatal("second allow should be denied")
	}
	Flush()

	m := moduleStats(t, Default().Snapshot(), "limiter_conn", "conn-1", "")
	if m.Limiter == nil || m.Limiter.Calls != 2 || m.Limiter.Allowed != 1 || m.Limiter.Denied != 1 {
		t.Fatalf("limiter stats = %+v", m.Limiter)
	}
}
```

Add analogous tests for rate and traffic with the same shape (`limiter_rate`, `limiter_traffic`), and a `Close` forwarding assertion.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./dashboard/ -run 'TestWrap.*LimiterExposesStats' -v`
Expected: FAIL (compile error: `WrapConnLimiter`/`Limiter` field undefined)

- [ ] **Step 3: Add LimiterStats to the DTOs**

In `x/dashboard/snapshot.go`:

```go
type LimiterStats struct {
	Calls     uint64 `json:"calls"`
	Allowed   uint64 `json:"allowed"`
	Denied    uint64 `json:"denied"`
	WaitCalls uint64 `json:"waitCalls"`
	Requested uint64 `json:"requested"`
	Granted   uint64 `json:"granted"`
}
```

Add `Limiter *LimiterStats \`json:"limiter,omitempty"\`` to `ModuleStats`. Add the same pointer field to `ModuleStatsEvent` in `event.go`.

- [ ] **Step 4: Add the sample callback and wire Flush/Observe**

In `x/dashboard/module.go`:
- Add `sampleLimiter atomic.Pointer[func() LimiterStats]` to `moduleCounters`.
- In `snapshot()`, if a sample is loaded, call it and set `ModuleStats.Limiter`.
- In `Flush`, copy `stats.Limiter` into the event.

In `x/dashboard/collector.go`, copy `e.Limiter` into `ModuleStats.Limiter` in `Observe`.

- [ ] **Step 5: Implement the wrappers**

`x/dashboard/limiter.go`:
- `WrapConnLimiter`, `WrapRateLimiter`, `WrapTrafficLimiter` create a `seriesSet` named `limiter_conn`/`limiter_rate`/`limiter_traffic`, capture `Stats()` from the inner limiter, and publish the sample callback atomically on the series counter:
  ```go
  c := w.set.get("")
  c.sampleLimiter.Store(&fn)
  ```
- Delegating methods: `Limiter(key)`, `In`/`Out`, `Close`.
- `Close` forwards via `closeModule`.

- [ ] **Step 6: Enable limiter stats from Apply**

In `x/dashboard/apply.go`, import `limiterstats "github.com/go-gost/x/limiter/stats"` and call `limiterstats.Enable(on)` alongside `Enable(on)`.

- [ ] **Step 7: Wrap the limiters in the loader**

In `x/config/loader/loader.go`, wrap the parsed limiter before registration:
- `dashboard.WrapTrafficLimiter(c.Name, limiter_parser.ParseLimiter(c))`
- `dashboard.WrapConnLimiter(c.Name, conn_limiter_parser.ParseLimiter(c))`
- `dashboard.WrapRateLimiter(c.Name, rate_limiter_parser.ParseLimiter(c))`

Also wrap before `Register` in the three REST handlers:
- `api/config_limiter.go`: `registry.TrafficLimiterRegistry().Register(name, dashboard.WrapTrafficLimiter(name, v))`
- `api/config_conn_limiter.go`: `registry.ConnLimiterRegistry().Register(name, dashboard.WrapConnLimiter(name, v))`
- `api/config_rate_limiter.go`: `registry.RateLimiterRegistry().Register(name, dashboard.WrapRateLimiter(name, v))`

Use the existing parser package aliases in `loader.go`.

- [ ] **Step 8: Run the wrapper tests**

Run: `go test ./dashboard/ -run 'TestWrap.*LimiterExposesStats' -v`
Expected: PASS

- [ ] **Step 9: Run package tests, race, vet, build**

Run: `go test ./dashboard/ ./limiter/... ./metrics/ ./config/loader/ -count=1`
Run: `go test -race ./dashboard/ ./limiter/... ./metrics/ -count=1`
Run: `go vet ./dashboard/ ./limiter/... ./metrics/ ./config/loader/`
Run: `cd gost && go build ./cmd/gost`
Expected: all PASS, build exit 0

- [ ] **Step 10: Commit**

```bash
git add dashboard limiter/stats config/loader
git commit -m "feat(dashboard): expose limiter stats"
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
- Modify: `x/docs/plans/2026-11-10-gost-dashboard-phase4.md`
- Modify: `.memory/notes/gost-dashboard-port-eval.md`

- [ ] **Step 1: Run the full affected suite**

Run: `go test ./dashboard/ ./limiter/... ./metrics/ ./resolver/ ./internal/util/resolver/ ./config/loader/ ./api/ ./chain/ -count=1`
Expected: PASS

- [ ] **Step 2: Run race tests**

Run: `go test -race ./dashboard/ ./limiter/... ./metrics/ -count=1`
Expected: PASS

- [ ] **Step 3: Run vet and build**

Run: `go vet ./dashboard/ ./limiter/... ./metrics/ ./config/loader/`
Run: `cd gost && go build ./cmd/gost`
Expected: clean, exit 0

- [ ] **Step 4: Confirm the committed tree is clean**

Run: `git status --short` and confirm only the pre-existing untracked docs remain. Re-run the suite from a clean checkout if anything was uncommitted.

- [ ] **Step 5: Fill in the implementation records**

Fill in Tasks 1-3 and add the Task 4 record.

- [ ] **Step 6: Update the memory note**

Add Phase 4 facts to `.memory/notes/gost-dashboard-port-eval.md` and commit in the memory repo:

```bash
cd /root/code/go-gost && git add .memory/notes/gost-dashboard-port-eval.md && git commit -m "docs(memory): record dashboard phase 4"
```

- [ ] **Step 7: Commit**

```bash
git add docs/plans/2026-11-10-gost-dashboard-phase4.md
git commit -m "docs(plans): record dashboard phase 4 implementation"
```

**Implementation record:**
- Date/status: _to fill_
- Repo + commit: _to fill_
- Files changed: _to fill_
- Tests/commands and results: _to fill_
- Review findings and fixes: _to fill_
- Deferred items/limitations: _to fill_
