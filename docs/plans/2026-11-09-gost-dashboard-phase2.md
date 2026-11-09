# GOST Dashboard Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add auther instrumentation and expose existing chain/node Prometheus counters as dashboard modules, so the overview can show chain activity without new hot-path instrumentation.

**Architecture:** Auther uses the Phase 1 wrapper machinery (atomic counters + reporter). Chain/node stats are read from `xmetrics.Registry()` on the reporter tick and merged into the collector's reserved `chains` map; `route.go` attributes errors to the failing hop and observes each successful hop's connect duration. Limiter and resolver-cache instrumentation are deferred (see Non-Goals).

**Tech Stack:** Go (x module), `github.com/go-gost/core/auth`, `github.com/prometheus/client_golang`, `dto "github.com/prometheus/client_model/go"`, standard `testing`.

**Spec:** `x/docs/plans/2026-11-09-gost-dashboard-phase0.md`, `...phase1.md`, `.memory/notes/gost-dashboard-port-eval.md`.

## Global Constraints

- Do **not** modify `core/`.
- Auther is wrapped once, at the loader and at the REST registration sites; never edit call sites.
- Chain stats come from the existing `gost_chain_errors_total` and `gost_chain_node_connect_duration_seconds` metrics. Do not add per-hop byte counters (nested connections double-count). `route.go` may label errors and durations per hop, but must not add new metric families.
- Chain metrics are process-cumulative Prometheus counters: they survive config reloads. Document this; do not try to reset them.
- Keys stay low-cardinality: `chain` and `node` names only.
- Auther `Authenticate` has no error return; success counts as a hit, failure as a miss. Credentials and usernames must never enter counters or events.
- Wrappers forward `io.Closer`.
- Code comments in English only; tests run per package.
- Plans carry per-task Implementation records; commit after each completed task (commit only, never push).

## Review Focus

- **Auther hot path:** authentication is on every client connection; the wrapper must not allocate when no options are passed and must not log or store credentials.
- **Service attribution:** auther options carry `Service`; some callers may omit it and land under `Service=""`.
- **Chain metric parsing:** the `host` label must be ignored; histogram sum/count must convert to micros and count correctly.
- **Stale chain rows:** removed chains stay in Prometheus; the dashboard must not crash on unknown labels and must not fabricate hop names.
- **Registry concurrency:** `Gather()` can race with metric registration? It is Prometheus's own safe gather; do not hold the collector lock while gathering.
- **No double counting:** chain errors/duration are already counted by Prometheus; do not add another counter.

## Data Contract

Auther reuses `ModuleStatsEvent` with `Kind="auther"`. `hits` = authenticated, `misses` = rejected. `Service` from `auth.WithService(...)`.

Chain stats fill the reserved `ChainSnapshot` fields. `Hops` stays empty (the dashboard merges topology from `/config`); per-node rows are exposed as a flat `nodes` list:

```json
"chains": {
  "chain-0": {
    "name": "chain-0",
    "nodes": [
      { "name": "node-0", "stats": { "connects": 3, "errors": 1, "connectDurationSumMicros": 1200, "connectCount": 3 } }
    ],
    "stats": { "connects": 3, "errors": 1, "connectDurationSumMicros": 1200, "connectCount": 3 }
  }
}
```

`NodeSnapshot` gains `Stats ChainStats`. `connects` equals `connectCount` because the duration histogram is observed only on successful connects. Per-node error rows are attributed to the failing hop; per-node duration rows are observed for each successful hop. `Snapshot` gains `metricsEnabled`: chain stats are empty when metrics are disabled, and the UI can surface that dependency.

---

## File Structure

```
x/dashboard/
  wrap.go          WrapAuther added
  chains.go        CollectChainStats + chainGatherer seam
  snapshot.go      ChainSnapshot.Nodes, NodeSnapshot.Stats, Snapshot.MetricsEnabled
  collector.go     ObserveChains (clears on empty)
  module.go        Flush merges chain stats
  wrap_test.go     auther wrapper tests
  chains_test.go   synthetic, real-registry, malformed-label, and multi-node tests
x/chain/route.go        per-hop error/duration attribution
x/chain/route_test.go   per-hop metric tests
x/config/loader/loader.go   wrap auther
x/api/config_auther.go      wrap auther at Register; reject nil parsers
```

---

### Task 1: Auther wrapper

**Files:**
- Modify: `x/dashboard/wrap.go`
- Modify: `x/dashboard/wrap_test.go`
- Modify: `x/config/loader/loader.go`
- Modify: `x/config/loader/loader_test.go`
- Modify: `x/api/config_auther.go`

**Interfaces:**
- Produces:
  - `func WrapAuther(name string, next auth.Authenticator) auth.Authenticator`
  - `var _ auth.Authenticator = (*autherWrapper)(nil)` and `var _ io.Closer = (*autherWrapper)(nil)`

- [ ] **Step 1: Write the failing tests**

`x/dashboard/wrap_test.go` additions:

```go
type fakeAuther struct {
    ok     bool
    closed bool
}

func (f *fakeAuther) Authenticate(context.Context, string, string, ...auth.Option) (string, bool) {
    return "", f.ok
}
func (f *fakeAuther) Close() error { f.closed = true; return nil }

func TestWrapAutherRecordsPerService(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    au := WrapAuther("users", &fakeAuther{ok: true})
    au.Authenticate(context.Background(), "u", "p", auth.WithService("svc-a"))
    au.Authenticate(context.Background(), "u", "p", auth.WithService("svc-b"))
    Flush()

    a := moduleStats(t, Default().Snapshot(), "auther", "users", "svc-a")
    b := moduleStats(t, Default().Snapshot(), "auther", "users", "svc-b")
    if a.Calls != 1 || a.Hits != 1 { t.Fatalf("svc-a = %+v", a) }
    if b.Calls != 1 || b.Hits != 1 { t.Fatalf("svc-b = %+v", b) }
}

func TestWrapAutherFailureIsMissAndCloseReachesInner(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    inner := &fakeAuther{ok: false}
    au := WrapAuther("users", inner)
    _, ok := au.Authenticate(context.Background(), "u", "bad")
    if ok { t.Fatal("expected failure") }
    Flush()
    got := moduleStats(t, Default().Snapshot(), "auther", "users", "")
    if got.Calls != 1 || got.Misses != 1 { t.Fatalf("got %+v", got) }

    if err := au.(io.Closer).Close(); err != nil { t.Fatal(err) }
    if !inner.closed { t.Fatal("Close did not reach the wrapped auther") }
}
```

`x/config/loader/loader_test.go` — extend the dashboard module test with an auther subtest:

```go
t.Run("auther", func(t *testing.T) {
    dashboard.ResetState()
    name := "test-auther-metrics"
    r := registry.AutherRegistry()
    t.Cleanup(func() { r.Unregister(name) })

    cfg := &config.Config{Authers: []*config.AutherConfig{{
        Name:  name,
        Auths: []*config.AuthConfig{{Username: "u", Password: "p"}},
    }}}
    if err := register(cfg); err != nil { t.Fatalf("register: %v", err) }

    au := r.Get(name)
    if au == nil { t.Fatal("auther not registered") }
    au.Authenticate(context.Background(), "u", "p", auth.WithService("svc"))
    dashboard.Flush()
    assertDashboardModule(t, "auther", name, "svc", 1)
})
```

Add the `auth` import.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ -run TestWrapAuther -v`
Expected: FAIL because `WrapAuther` does not exist.
Run: `cd x && go test ./config/loader/ -run 'TestRegister_ModulesReportToDashboard/auther' -v`
Expected: FAIL because the registered auther is unwrapped.

- [ ] **Step 3: Implement the wrapper and wiring**

`wrap.go`:
```go
type autherWrapper struct {
    next auth.Authenticator
    set  *seriesSet
}

func WrapAuther(name string, next auth.Authenticator) auth.Authenticator {
    if !Enabled() || next == nil { return next }
    return &autherWrapper{next: next, set: newSeriesSet("auther", name)}
}

func (w *autherWrapper) Authenticate(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
    var o auth.Options
    if len(opts) > 0 {
        for _, opt := range opts { opt(&o) }
    }
    start := time.Now()
    id, ok := w.next.Authenticate(ctx, user, pass, opts...)
    c := w.set.get(o.Service)
    c.observe(start)
    if ok { c.hit() } else { c.miss() }
    return id, ok
}

func (w *autherWrapper) Close() error { return closeModule(w.next) }
```

`loader.go`: wrap the `ParseAutherWithError` result. `api/config_auther.go`: wrap `parser.ParseAuther` in both create and update `Register` calls.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ ./config/loader/ -run 'TestWrapAuther|TestRegister_ModulesReportToDashboard' -v`
Expected: PASS.

- [ ] **Step 5: Race and vet**

Run: `cd x && go test -race ./dashboard/ ./config/loader/ -count=1 && go vet ./dashboard/ ./config/loader/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git -C x add dashboard config/loader api/config_auther.go
git -C x commit -m "feat(dashboard): instrument auther"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `a89b08a` (code); record follows in a docs-only commit.
- Files changed: `x/dashboard/wrap.go`, `x/dashboard/wrap_test.go`, `x/config/loader/loader.go`, `x/config/loader/loader_test.go`, `x/api/config_auther.go`.
- Tests/commands and results: `go test ./dashboard/ ./api/ ./config/loader/ -count=1` → PASS; `go test -race ./dashboard/ ./config/loader/ -count=1` → PASS; `go vet` → clean; loader integration covers bypass/admission/hosts/resolver/auther.
- Review findings and fixes: none specific to this task.
- Deferred items/limitations: some callers may omit `auth.WithService`, so those authentications land under `Service=""`; credentials are never recorded.

---

### Task 2: Chain/node metrics from the Prometheus registry

**Files:**
- Create: `x/dashboard/chains.go`
- Create: `x/dashboard/chains_test.go`
- Modify: `x/dashboard/snapshot.go` (`ChainSnapshot.Nodes`, `NodeSnapshot.Stats`)
- Modify: `x/dashboard/collector.go` (`ObserveChains`)
- Modify: `x/dashboard/module.go` (`Flush` merges chain stats)

**Interfaces:**
- Produces:
  - `var chainGatherer = func() ([]*dto.MetricFamily, error)` (test seam, real registry by default)
  - `func CollectChainStats() map[string]*ChainSnapshot`
  - `func (c *Collector) ObserveChains(chains map[string]*ChainSnapshot)`
  - `Snapshot.Chains["<chain>"].Nodes[].Stats` and `.Stats`

- [ ] **Step 1: Write the failing tests**

`x/dashboard/chains_test.go`:

```go
func TestCollectChainStatsFromMetrics(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    orig := chainGatherer
    defer func() { chainGatherer = orig }()

    chainGatherer = func() ([]*dto.MetricFamily, error) {
        return []*dto.MetricFamily{
            {
                Name: proto.String("gost_chain_errors_total"),
                Type: dto.MetricType_COUNTER.Enum(),
                Metric: []*dto.Metric{{
                    Label: []*dto.LabelPair{
                        {Name: proto.String("host"), Value: proto.String("h")},
                        {Name: proto.String("chain"), Value: proto.String("chain-0")},
                        {Name: proto.String("node"), Value: proto.String("node-0")},
                    },
                    Counter: &dto.Counter{Value: proto.Float64(2)},
                }},
            },
            {
                Name: proto.String("gost_chain_node_connect_duration_seconds"),
                Type: dto.MetricType_HISTOGRAM.Enum(),
                Metric: []*dto.Metric{{
                    Label: []*dto.LabelPair{
                        {Name: proto.String("host"), Value: proto.String("h")},
                        {Name: proto.String("chain"), Value: proto.String("chain-0")},
                        {Name: proto.String("node"), Value: proto.String("node-0")},
                    },
                    Histogram: &dto.Histogram{SampleCount: proto.Uint64(3), SampleSum: proto.Float64(0.006)},
                }},
            },
        }, nil
    }

    Flush()
    snap := Default().Snapshot()
    cs := snap.Chains["chain-0"]
    if cs == nil { t.Fatal("chain not found") }
    if cs.Stats.Errors != 2 || cs.Stats.ConnectCount != 3 || cs.Stats.Connects != 3 {
        t.Fatalf("chain stats = %+v", cs.Stats)
    }
    if cs.Stats.ConnectDurationSumMicros != 6000 {
        t.Fatalf("duration micros = %d, want 6000", cs.Stats.ConnectDurationSumMicros)
    }
    if len(cs.Nodes) != 1 || cs.Nodes[0].Name != "node-0" || cs.Nodes[0].Stats.Errors != 2 {
        t.Fatalf("nodes = %+v", cs.Nodes)
    }
}

func TestCollectChainStatsIgnoresUnknownMetrics(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    orig := chainGatherer
    defer func() { chainGatherer = orig }()
    chainGatherer = func() ([]*dto.MetricFamily, error) { return nil, nil }

    if got := CollectChainStats(); got != nil {
        t.Fatalf("got %+v, want nil", got)
    }
}
```

Also a real-registry test:

```go
func TestCollectChainStatsReadsPrometheusRegistry(t *testing.T) {
    ResetState()
    Enable(true)
    defer Enable(false)

    origEnabled := xmetrics.IsEnabled()
    xmetrics.Enable(true)
    defer xmetrics.Enable(origEnabled)

    chainName, nodeName := "test-collect-chain", "test-collect-node"
    if v := xmetrics.GetCounter(xmetrics.MetricChainErrorsCounter,
        metrics.Labels{"chain": chainName, "node": nodeName}); v != nil {
        v.Inc()
    }
    if v := xmetrics.GetObserver(xmetrics.MetricNodeConnectDurationObserver,
        metrics.Labels{"chain": chainName, "node": nodeName}); v != nil {
        v.Observe(0.002)
    }

    Flush()
    cs := Default().Snapshot().Chains[chainName]
    if cs == nil || cs.Stats.Errors != 1 || cs.Stats.ConnectCount != 1 {
        t.Fatalf("chain stats = %+v", cs)
    }
}
```

Add imports `dto`, `proto`, `metrics` (core), `xmetrics`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ -run TestCollectChainStats -v`
Expected: FAIL because `CollectChainStats`, `ObserveChains`, and the new DTO fields do not exist.

- [ ] **Step 3: Implement `chains.go`, DTOs, and merge**

- `ChainSnapshot` gains `Nodes []NodeSnapshot \`json:"nodes,omitempty"\``.
- `NodeSnapshot` gains `Stats ChainStats \`json:"stats,omitempty"\``.
- `chainGatherer` defaults to `xmetrics.Registry().Gather`.
- `CollectChainStats` iterates families by name, reads `host`/`chain`/`node` labels (ignore `host`), and builds per-chain aggregate plus per-node stats. Unknown families and malformed labels are skipped. Returns `nil` when there is nothing.
- `Collector.ObserveChains` replaces `c.chains` wholesale (metrics are authoritative, cumulative) under the write lock.
- `Flush` calls `ObserveChains(CollectChainStats())` after the module event batch.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ -run TestCollectChainStats -v`
Expected: PASS.

- [ ] **Step 5: Full package tests, race, vet, build**

Run: `cd x && go test ./dashboard/ ./api/ ./config/loader/ ./hosts/ -count=1`
Run: `cd x && go test -race ./dashboard/ -count=1 && go vet ./dashboard/ ./api/ ./config/loader/`
Run: `cd gost && go build ./cmd/gost`
Expected: PASS, exit 0.

- [ ] **Step 6: End-to-end smoke**

Start the binary with `dashboard.enabled=true`, `metrics.addr` set, and a service using a chain; drive one connection through the chain; after the reporter tick, `GET /dashboard/snapshot` must show `chains.<name>.stats.errors`/`connectCount` matching the Prometheus counters. Stop the process.

- [ ] **Step 7: Commit**

```bash
git -C x add dashboard
git -C x commit -m "feat(dashboard): expose chain and node metrics"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `24f1fd4` (code); record follows in a docs-only commit.
- Files changed: `x/dashboard/chains.go`, `x/dashboard/chains_test.go`, `x/dashboard/snapshot.go`, `x/dashboard/collector.go`, `x/dashboard/module.go`.
- Tests/commands and results: `go test ./dashboard/ ./api/ ./config/loader/ ./hosts/ -count=1` → PASS; `go test -race ./dashboard/ ./config/loader/ -count=1` → PASS; `go vet` → clean; `cd gost && go build ./cmd/gost` → exit 0.
- End-to-end smoke: ran the binary with `dashboard.enabled=true`, `metrics.addr=127.0.0.1:19090`, an HTTP service chained through `chain-0` to a local HTTP server; one forced proxy request returned 200, and the snapshot contained `chains.chain-0.nodes[0].stats = {connects:1, connectCount:1, connectDurationSumMicros:227, errors:0}` plus the matching chain aggregate. Process and backend stopped afterwards.
- Review findings and fixes: none specific to this task; the real-registry test (`TestCollectChainStatsReadsPrometheusRegistry`) pins the Prometheus integration instead of only synthetic families.
- Deferred items/limitations: chain metrics are process-cumulative and persist across reloads; `Gather()` runs every reporter tick and includes all metric families, so a very large deployment may want a family filter; removed chains remain in Prometheus until process restart.

---

### Phase 2 final review

A fresh-context review of `0898532..3a24917` found no Critical issues; verdict **fix-then-ship**. Important findings:

1. Multi-hop chains were only instrumented for the first node: `route.go` labeled every error with `nodes[0]` and observed connect duration only for `nodes[0]`, so a failing second hop was attributed to the first hop and per-node stats were misleading. Fixed in Task 3: `route.go` tracks the failing hop and observes each successful hop's connect duration.
2. `Flush` gathers the entire Prometheus registry every 5 s. Documented as a scaling limitation; a family-filtered gather is deferred (see Handoff Notes).
3. Chain stats were silently empty when metrics were disabled. Fixed in Task 3: `Snapshot.metricsEnabled` exposes the dependency and the Data Contract documents it.
4. Removed chains reappear after reload because chain metrics are process-cumulative. Documented as a limitation; filtering by current config is deferred.

Minors addressed in Task 3: `ObserveChains` now clears stale rows on empty input; `go.mod` marks `prometheus/client_model` as a direct dependency; the dead `omitempty` tag on `NodeSnapshot.Stats` was removed; tests cover malformed/missing labels, multiple nodes, empty observe, metrics-disabled snapshots, and repeated real-registry runs; the REST auther endpoints reject nil parsers. `Gather` errors still clear the chain map rather than logging; no logger is available in the dashboard package.

---

### Task 3: Phase 2 review fixes

**Files:**
- Modify: `x/chain/route.go`, `x/chain/route_test.go`
- Modify: `x/dashboard/collector.go`, `x/dashboard/snapshot.go`, `x/dashboard/chains_test.go`
- Modify: `x/api/config_auther.go`
- Modify: `x/go.mod`

**Interfaces:**
- Produces: per-hop `gost_chain_errors_total` and `gost_chain_node_connect_duration_seconds`; `Snapshot.MetricsEnabled`.

- [x] **Step 1: Write failing tests for per-hop attribution and empty-observe clearing.**
- [x] **Step 2: Run tests to verify they fail.**
- [x] **Step 3: Implement per-hop error attribution and duration observation in `route.go`.**
- [x] **Step 4: Add `Snapshot.MetricsEnabled`, clear chains on empty observe, and reject nil authers at the REST boundary.**
- [x] **Step 5: Run package tests, race, vet, `go mod tidy -diff`, and the gost build.**
- [x] **Step 6: Commit.**

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `ecd42ac` (code); this record follows in a docs-only commit.
- Files changed: `x/chain/route.go`, `x/chain/route_test.go`, `x/dashboard/collector.go`, `x/dashboard/snapshot.go`, `x/dashboard/chains_test.go`, `x/api/config_auther.go`, `x/go.mod`.
- Tests/commands and results: `go test ./dashboard/ ./api/ ./config/loader/ ./hosts/ ./chain/ -count=1` → PASS; `go test -race ./dashboard/ ./config/loader/ ./chain/ -count=1` → PASS; `go test ./dashboard/ -count=2` → PASS; `go vet ./dashboard/ ./api/ ./config/loader/ ./chain/` → clean; `go mod tidy -diff` → empty; `cd gost && go build ./cmd/gost` → exit 0.
- Review findings and fixes: #1 per-hop error/duration attribution fixed in `route.go`; #3 metrics-disabled dependency fixed with `Snapshot.MetricsEnabled`; #5 `ObserveChains` clears on empty; #6 `prometheus/client_model` moved to direct dependencies; #7 dead `omitempty` removed; #8 added malformed-label, multi-node, empty-observe, metrics-disabled, and repeat-run tests; #10 REST auther endpoints reject nil parsers. #2 and #4 remain documented limitations.
- Deferred items/limitations: `Gather()` runs every reporter tick over all families; chain metrics are process-cumulative and survive reloads; `Gather` errors clear the chain map without logging.

---

## Phase 2 Non-Goals

- No limiter instrumentation: conn/rate limiters key by client IP or service (high cardinality), and the traffic limiter is called per byte. Wrapping would either explode the series map or add hot-path allocation; defer until a design exists for aggregate-only limiter stats.
- No resolver cache hit/miss: the cache decision is inside `localResolver`; needs an internal counter hook and a way for the wrapper to read it.
- No admission service attribution for conn wrappers (carried over from Phase 1).
- No per-hop traffic bytes (nested connections double-count).
- No frontend work.

## Handoff Notes

- Chain stats are read from the same Prometheus registry Grafana uses; they are process-cumulative and persist across reloads. If a future phase needs reload-scoped chain stats, filter by the current config's chain names in `Apply`.
- Chain stats require metrics to be enabled (`metrics.addr`); `Snapshot.metricsEnabled` reports the dependency so the UI can explain empty `chains`.
- `route.go` attributes errors to the failing hop and observes each successful hop's connect duration; per-node dashboard rows are accurate for multi-hop chains.
- `Flush` gathers the full Prometheus registry every 5 s. A family-filtered gather in `x/metrics` would reduce the cost for very large deployments; it is deferred.
- The auther wrapper counts only success/failure; it never records the username or credentials.
- Phase 3 can add limiter aggregates (counters only, no per-key series) and the resolver cache hook using the same reporter.
