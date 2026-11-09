# GOST Dashboard Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Instrument the P0 module boundaries — bypass, admission, hosts, resolver — with low-overhead counters and feed them to the Phase 0 collector as cumulative `ModuleStatsEvent` snapshots.

**Architecture:** Wrap the four module instances once, at registry construction in `x/config/loader`, so every caller is measured without editing call sites. Wrappers own atomic counters keyed by `(kind, name, service)`; a single 5-second reporter in `x/dashboard` converts them into `ModuleStatsEvent` batches and calls the collector directly (never through external observer plugins).

**Tech Stack:** Go (x module), `github.com/go-gost/core/{bypass,admission,hosts,resolver}`, `sync/atomic`, `sync.Map`, standard `testing`.

**Spec:** `x/docs/plans/2026-11-09-gost-dashboard-phase0.md` (event contract and collector) plus `.memory/notes/gost-dashboard-port-eval.md`.

## Global Constraints

- Do **not** modify `core/`; wrappers implement the existing interfaces in `x/dashboard`.
- Do **not** edit the ~48 `.Contains(` / 11 `.Admit(` / 10 `.Lookup(` / 10 `.Resolve(` call sites. One wrap point per module in `x/config/loader`.
- Observe must stay cheap: at most one `sync.Map` load and two `time.Now` calls per instrumented invocation; no allocation in the hot path beyond the varargs slice the caller already passes.
- Counters are **cumulative**; the reporter never sends deltas. Retried/repeated reports must be idempotent.
- Attribution: bypass/admission read `Options.Service` from call options; hosts/resolver are shared and use `Service=""`.
- Exposed keys stay low-cardinality. Never expose client IP, hostname, domain, or URL.
- Module error events are emitted by the reporter (at most one per increase), never per call, and carry `Seq` equal to the cumulative error count so the Phase 0 collector deduplicates retries.
- External observer plugins must never receive module events: the reporter calls `Default().Observe` directly.
- Code comments in English only; tests run per package (`cd x && go test ./dashboard/ ./config/loader/`).
- Plans carry per-task Implementation records; commit after each completed task (commit only, never push).

## Review Focus

- **Hot-path cost:** bypass is called on every forwarded connection; the wrapper must not take a mutex or allocate maps per call.
- **Attribution leaks:** one named rule used by many services must produce one series per service, not a merged total.
- **Shared modules:** hosts/resolver must stay `Service=""` even when called from a service, so the frontend does not draw fake per-service edges.
- **Reporter lifetime:** `Apply` on every reload must stop the old ticker before starting a new one; disabling must stop it entirely.
- **Reset ordering:** `Apply` resets series state before `loader.Load` rebuilds wrappers; stale counters from the previous config must not leak into the new one.
- **Semantics per module:** bypass/admission `hits` = allowed match, `misses` = not matched/denied; hosts `hits` = mapping found; resolver `hits` = IPs returned, `misses` = empty result, `errors` = returned error.

## Data Contract

Phase 1 reuses the Phase 0 `ModuleStatsEvent` and `ModuleErrorEvent` types. No new event type and no snapshot schema change.

Series identity:

| Module | `Kind` | `Name` | `Service` |
|---|---|---|---|
| bypass | `bypass` | configured name | `bypass.WithService(...)` value, else `""` |
| admission | `admission` | configured name | `admission.WithService(...)` value, else `""` |
| hosts | `hosts` | configured name | `""` |
| resolver | `resolver` | configured name | `""` |

Counters per series: `calls`, `hits`, `misses`, `errors`, `latencySumMicros`, `latencyCount`. `InputBytes`/`OutputBytes` stay zero — these modules carry no payload.

---

## File Structure

```
x/dashboard/
  module.go        moduleCounters, seriesSet, global series registry, Flush, ResetState
  wrap.go          WrapBypass / WrapAdmission / WrapHosts / WrapResolver
  apply.go         reporter lifecycle added to Apply (start/stop ticker)
  module_test.go
  wrap_test.go
  apply_test.go    (extend existing multi_test.go or new file)
x/config/loader/
  loader.go        wrap the four parsed instances before Register
  loader_test.go   integration assertions that registry instances are wrapped
```

---

### Task 1: Counter registry and synchronous flush

**Files:**
- Create: `x/dashboard/module.go`
- Create: `x/dashboard/module_test.go`
- Modify: `x/dashboard/apply.go` (`ResetState` hook, reporter later)
- Modify: `x/dashboard/collector.go` (no change expected; `Reset` stays)

**Interfaces:**
- Consumes: `Key`, `ModuleStatsEvent`, `ModuleErrorEvent`, `Default()`, `Enabled()` from Phase 0.
- Produces:
  - `type moduleCounters struct { calls, hits, misses, errors, latencySum, latencyCount atomic.Uint64; lastErrReported atomic.Uint64 }`
  - `type seriesSet struct { kind, name string; byService sync.Map }`
  - `func newSeriesSet(kind, name string) *seriesSet`
  - `func (s *seriesSet) get(service string) *moduleCounters`
  - `func Flush()` — emits one cumulative batch to `Default()`.
  - `func ResetState()` — `Default().Reset()` plus clearing the global series registry.

- [ ] **Step 1: Write the failing tests**

`x/dashboard/module_test.go`:

```go
func TestSeriesSetRegistersPerService(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    set := newSeriesSet("bypass", "direct")
    a := set.get("svc-a")
    b := set.get("svc-b")
    a.calls.Add(3)
    b.calls.Add(5)

    Flush()
    snap := Default().Snapshot()
    if got := moduleStats(t, snap, "bypass", "direct", "svc-a").Calls; got != 3 {
        t.Fatalf("svc-a calls = %d, want 3", got)
    }
    if got := moduleStats(t, snap, "bypass", "direct", "svc-b").Calls; got != 5 {
        t.Fatalf("svc-b calls = %d, want 5", got)
    }
}

func TestFlushEmitsOneErrorEventPerIncrease(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    set := newSeriesSet("resolver", "local")
    c := set.get("")
    c.calls.Add(2)
    c.errors.Add(1)

    Flush()
    Flush()
    snap := Default().Snapshot()
    if got := len(snap.Events); got != 1 {
        t.Fatalf("events = %d, want 1 after repeated flush", got)
    }

    c.errors.Add(1)
    Flush()
    if got := len(Default().Snapshot().Events); got != 2 {
        t.Fatalf("events = %d, want 2 after new error", got)
    }
}

func TestResetStateClearsSeries(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    set := newSeriesSet("hosts", "local")
    set.get("").calls.Add(1)
    Flush()
    if len(Default().Snapshot().Modules) != 1 {
        t.Fatal("expected one module before reset")
    }

    ResetState()
    Flush()
    if got := len(Default().Snapshot().Modules); got != 0 {
        t.Fatalf("modules after reset = %d, want 0", got)
    }
}
```

Add a helper `moduleStats(t, snap, kind, name, service)` that finds the matching `ModuleSnapshot` and fails when absent.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ -run 'TestSeries|TestFlush|TestResetState' -v`
Expected: FAIL because `newSeriesSet`, `Flush`, and `ResetState` do not exist.

- [ ] **Step 3: Implement `module.go`**

- `moduleCounters` uses `atomic.Uint64`; no mutex.
- `seriesSet.get(service)` uses `sync.Map.LoadOrStore` keyed by service string; the created `moduleCounters` is also stored in the package-level `series sync.Map` keyed by `Key{Kind, Name, Service}`.
- `Flush()` ranges `series`, reads counters, appends one `ModuleStatsEvent` per key, and appends a `ModuleErrorEvent{Seq: errors, Message: errorMessage(kind)}` when `errors > lastErrReported` (use `Swap`). Then calls `Default().Observe(context.Background(), events)` once.
- `errorMessage` returns a generic string (`"resolver error"`); never include a host or address.
- `ResetState()` calls `Default().Reset()` and deletes every key in `series`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ -run 'TestSeries|TestFlush|TestResetState' -v`
Expected: PASS.

- [ ] **Step 5: Race and vet**

Run: `cd x && go test -race ./dashboard/ -count=1 && go vet ./dashboard/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git -C x add dashboard
git -C x commit -m "feat(dashboard): add module counter registry and flush"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `8507161` (code); record follows in a docs-only commit.
- Files changed: `x/dashboard/module.go`, `x/dashboard/module_test.go`.
- Tests/commands and results: `go test ./dashboard/ -run 'TestSeries|TestFlush|TestResetState|TestStale' -v` → 4/4 PASS; `go test ./dashboard/ -count=1` → PASS; `go test -race ./dashboard/ -count=1` → PASS; `go vet` and `gofmt -l` → clean.
- Review findings and fixes: added a `seriesGen` epoch beyond the plan so a stale wrapper left over from a previous config cannot re-register counters after `ResetState`; pinned by `TestStaleSeriesSetDoesNotReRegister` (RED→GREEN).
- Deferred items/limitations: report interval is still fixed at 5s and the ticker arrives in Task 3; `ResetState` drops module history by design.

---

### Task 2: Module wrappers

**Files:**
- Create: `x/dashboard/wrap.go`
- Create: `x/dashboard/wrap_test.go`

**Interfaces:**
- Consumes: `newSeriesSet`, `moduleCounters` from Task 1.
- Produces:
  - `func WrapBypass(name string, next bypass.Bypass) bypass.Bypass`
  - `func WrapAdmission(name string, next admission.Admission) admission.Admission`
  - `func WrapHosts(name string, next hosts.HostMapper) hosts.HostMapper`
  - `func WrapResolver(name string, next resolver.Resolver) resolver.Resolver`

Each returns `next` unchanged when `!Enabled()` or `next == nil`.

- [ ] **Step 1: Write the failing tests**

`x/dashboard/wrap_test.go` must contain:

```go
type fakeBypass struct{ match bool }
func (f *fakeBypass) IsWhitelist() bool { return false }
func (f *fakeBypass) Contains(context.Context, string, string, ...bypass.Option) bool { return f.match }

type fakeAdmission struct{ allow bool }
func (f *fakeAdmission) Admit(context.Context, string, string, ...admission.Option) bool { return f.allow }

type fakeHosts struct{ ips []net.IP; ok bool }
func (f *fakeHosts) Lookup(context.Context, string, string, ...hosts.Option) ([]net.IP, bool) { return f.ips, f.ok }

type fakeResolver struct{ ips []net.IP; err error }
func (f *fakeResolver) Resolve(context.Context, string, string, ...resolver.Option) ([]net.IP, error) { return f.ips, f.err }

func TestWrapBypassRecordsPerService(t *testing.T) {
    ResetState(); Enable(true); defer Enable(false)

    bp := WrapBypass("direct", &fakeBypass{match: true})
    bp.Contains(context.Background(), "tcp", "example.com", bypass.WithService("svc-a"))
    bp.Contains(context.Background(), "tcp", "example.com", bypass.WithService("svc-b"))
    Flush()

    a := moduleStats(t, Default().Snapshot(), "bypass", "direct", "svc-a")
    b := moduleStats(t, Default().Snapshot(), "bypass", "direct", "svc-b")
    if a.Calls != 1 || a.Hits != 1 { t.Fatalf("svc-a = %+v", a) }
    if b.Calls != 1 || b.Hits != 1 { t.Fatalf("svc-b = %+v", b) }
}

func TestWrapAdmissionRecordsDenyAsMiss(t *testing.T) {
    ResetState(); Enable(true); defer Enable(false)

    adm := WrapAdmission("lan", &fakeAdmission{allow: false})
    adm.Admit(context.Background(), "tcp", "10.0.0.1:1", admission.WithService("svc"))
    Flush()

    got := moduleStats(t, Default().Snapshot(), "admission", "lan", "svc")
    if got.Calls != 1 || got.Misses != 1 || got.Hits != 0 { t.Fatalf("got %+v", got) }
}

func TestWrapHostsAndResolverAreShared(t *testing.T) {
    ResetState(); Enable(true); defer Enable(false)

    WrapHosts("local", &fakeHosts{ips: []net.IP{net.ParseIP("127.0.0.1")}, ok: true}).
        Lookup(context.Background(), "ip", "example.com")
    WrapResolver("local", &fakeResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}).
        Resolve(context.Background(), "ip", "example.com")
    Flush()

    snap := Default().Snapshot()
    moduleStats(t, snap, "hosts", "local", "").Hits++
    moduleStats(t, snap, "resolver", "local", "").Hits++
}

func TestWrapDisabledReturnsNext(t *testing.T) {
    Enable(false)
    bp := &fakeBypass{}
    if got := WrapBypass("direct", bp); got != bp {
        t.Fatal("disabled dashboard must return the original bypass")
    }
}
```

Add the missing imports (`net`, core interfaces) and assertions that resolver errors increment `Errors`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ -run TestWrap -v`
Expected: FAIL because `WrapBypass`, `WrapAdmission`, `WrapHosts`, `WrapResolver` do not exist.

- [ ] **Step 3: Implement `wrap.go`**

For each wrapper:

- Read the service from options (`var o bypass.Options; for _, opt := range opts { opt(&o) }`).
- `start := time.Now()`, call `next`, `c := set.get(o.Service)`, then `c.calls.Add(1)`, `c.latencySum.Add(uint64(time.Since(start).Microseconds()))`, `c.latencyCount.Add(1)`.
- Increment `hits`/`misses`/`errors` per the semantics table.
- Forward `IsWhitelist()` unchanged.

Use a shared helper `record(c *moduleCounters, hit bool, start time.Time)` for counters, with per-wrapper classification.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ -run TestWrap -v`
Expected: PASS.

- [ ] **Step 5: Race and vet**

Run: `cd x && go test -race ./dashboard/ -count=1 && go vet ./dashboard/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git -C x add dashboard
git -C x commit -m "feat(dashboard): wrap bypass, admission, hosts and resolver"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `e5c9753` (code); record follows in a docs-only commit.
- Files changed: `x/dashboard/wrap.go`, `x/dashboard/wrap_test.go`, `x/dashboard/collector.go`, `x/dashboard/collector_test.go`.
- Tests/commands and results: `go test ./dashboard/ -run 'TestWrap|TestCollector|TestSeries|TestFlush|TestReset' -count=1` → PASS; `go test ./dashboard/ -count=1` → PASS; `go test -race ./dashboard/ -count=1` → PASS; `go vet` and `gofmt -l` → clean.
- Review findings and fixes: while wiring the resolver error test, found that a batch carrying both `ModuleStatsEvent{Errors: N}` and `ModuleErrorEvent{Seq: N}` double-counted to `2N` in the collector. Fixed by reconciling `Seq` against the stored cumulative value (`max`) instead of incrementing; `TestCollectorErrorEventDoesNotDoubleCountCumulativeStats` RED→GREEN.
- Deferred items/limitations: no resolver cache hit/miss (needs an internal hook); latency is measured with `time.Now` on every call, which is acceptable but not free.

---

### Task 3: Loader wiring and reporter lifecycle

**Files:**
- Modify: `x/config/loader/loader.go` (4 registration blocks)
- Modify: `x/config/loader/loader_test.go` (integration assertions)
- Modify: `x/dashboard/apply.go` (start/stop ticker)
- Create/Modify: `x/dashboard/apply_test.go` (reporter lifecycle)

**Interfaces:**
- Consumes: `WrapBypass`, `WrapAdmission`, `WrapHosts`, `WrapResolver`, `ResetState` from Tasks 1–2.
- Produces: reporter goroutine started by `Apply` when enabled, stopped when disabled; `Flush()` remains the synchronous entry point.

- [ ] **Step 1: Write the failing tests**

`x/config/loader/loader_test.go` — extend `TestRegister_Bypasses` (or add a sibling) to prove the registered instance is wrapped:

```go
func TestRegister_BypassesReportsToDashboard(t *testing.T) {
	dashboard.ResetState()
	dashboard.Enable(true)
	t.Cleanup(func() { dashboard.Enable(false); dashboard.ResetState() })

	name := "test-bypass-metrics"
	r := registry.BypassRegistry()
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{Bypasses: []*config.BypassConfig{{Name: name, Matchers: []string{"127.0.0.1"}}}}
	if err := register(cfg); err != nil { t.Fatalf("register: %v", err) }

	bp := r.Get(name)
	if bp == nil { t.Fatal("bypass not registered") }
	bp.Contains(context.Background(), "tcp", "127.0.0.1", bypass.WithService("svc"))
	dashboard.Flush()

	snap := dashboard.Default().Snapshot()
	found := false
	for _, m := range snap.Modules {
		if m.Kind == "bypass" && m.Name == name && m.Service == "svc" && m.Stats.Calls == 1 {
			found = true
		}
	}
	if !found { t.Fatalf("bypass metrics missing: %+v", snap.Modules) }
}
```

Add analogous assertions for admission, hosts, and resolver? One module is enough to prove the loader pattern; add a table-driven test over the four registries if it stays readable. At minimum, assert each registry returns a wrapped instance by checking a call increments the series.

`x/dashboard/apply_test.go`:

```go
func TestApplyStartsAndStopsReporter(t *testing.T) {
	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: true}})
	if reporterCancel == nil {
		t.Fatal("reporter not started")
	}
	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: false}})
	if reporterCancel != nil {
		t.Fatal("reporter not stopped")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./config/loader/ -run TestRegister_BypassesReportsToDashboard -v`
Expected: FAIL because the registered bypass is not wrapped (no module event).
Run: `cd x && go test ./dashboard/ -run TestApplyStartsAndStopsReporter -v`
Expected: FAIL because `reporterCancel` does not exist.

- [ ] **Step 3: Implement loader wrapping and reporter lifecycle**

`loader.go` — wrap the four parse results in place:

```go
named[admission.Admission]{c.Name, dashboard.WrapAdmission(c.Name, admission_parser.ParseAdmission(c))}
named[bypass.Bypass]{c.Name, dashboard.WrapBypass(c.Name, bypass_parser.ParseBypass(c))}
named[resolver.Resolver]{c.Name, dashboard.WrapResolver(c.Name, r)}
named[hosts.HostMapper]{c.Name, dashboard.WrapHosts(c.Name, hosts_parser.ParseHostMapper(c))}
```

`apply.go`:

```go
var (
	reportInterval = 5 * time.Second
	reporterMu     sync.Mutex
	reporterCancel context.CancelFunc
)

func Apply(cfg *config.Config) {
	on := cfg != nil && cfg.Dashboard != nil && cfg.Dashboard.Enabled
	stopReporter()
	Enable(on)
	if !on {
		return
	}
	ResetState()
	startReporter()
}

func startReporter() { /* ticker -> Flush until ctx.Done */ }
func stopReporter()  { /* cancel and clear */ }
```

Order matters: `stopReporter` → `Enable` → `ResetState` → `startReporter`. `ResetState` clears series left by the previous config before `loader.Load` builds new wrappers.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./config/loader/ ./dashboard/ -run 'TestRegister_BypassesReportsToDashboard|TestApplyStartsAndStopsReporter' -v`
Expected: PASS.

- [ ] **Step 5: Full package tests and build**

Run: `cd x && go test ./dashboard/ ./config/loader/ ./config/... -count=1`
Run: `cd x && go test -race ./dashboard/ -count=1 && go vet ./dashboard/ ./config/loader/`
Run: `cd gost && go build ./cmd/gost`
Expected: all PASS, build exit 0.

- [ ] **Step 6: End-to-end smoke**

Start the built binary with a config that has `dashboard.enabled=true` and a bypass rule, drive one proxied connection through the service, then `GET /dashboard/snapshot` and confirm a `modules` entry with `kind="bypass"`, `calls >= 1`, and the service name. Stop the process afterwards.

- [ ] **Step 7: Commit**

```bash
git -C x add dashboard config/loader
git -C x commit -m "feat(dashboard): instrument module registries and run reporter"
```

**Implementation record:**
- Date/status: _pending_
- Repo + commit: _pending_
- Files changed: _pending_
- Tests/commands and results: _pending_
- Review findings and fixes: _pending_
- Deferred items/limitations: _pending_

---

## Phase 1 Non-Goals

- No auther, limiter, router, recorder, ingress, sd, chain/hop/node instrumentation (Phase 2+).
- No per-hop traffic counters (still double-counts nested connections).
- No resolver cache hit/miss (needs a hook inside `localResolver`).
- No config for the report interval; fixed 5s.
- No persistence, WebSocket, or frontend.

## Handoff Notes

- Phase 2 should add chain/hop/node connect events and auther/limiter wrappers using the same `seriesSet` + `Flush` machinery.
- Resolver cache hit/miss still needs an internal hook; the wrapper only sees `Resolve` calls.
- The reporter emits module events directly to the collector, so external HTTP/gRPC observer plugins remain untouched.
- `ResetState` on every reload intentionally drops module history; document it if a future phase persists history.
