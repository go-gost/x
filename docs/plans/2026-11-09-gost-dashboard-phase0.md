# GOST Dashboard Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dashboard-only read model to `x/` that consumes existing `observer` events and exposes one stable JSON snapshot at `GET /dashboard/snapshot`.

**Architecture:** `x/dashboard` owns the data contract, an in-process `Collector` that implements `core/observer.Observer`, a bounded event ring and a bounded 1-hour sample ring. `observer` stays the transport; `metrics` stays the Prometheus/latency source. Phase 0 does not add module wrappers — it proves the contract with the events already produced by services and handlers.

**Tech Stack:** Go (x module), `github.com/go-gost/core/observer`, `github.com/gin-gonic/gin`, standard `testing` + `httptest`.

**Spec:** this plan plus `.memory/notes/gost-dashboard-port-eval.md` (evaluation). Phase 0 is deliberately narrower than the earlier P0-wrapper proposal: no `x/observe`, no bypass/admission/resolver instrumentation yet.

## Global Constraints

- Do **not** modify `core/`; extend `observer.EventType` values inside `x/dashboard` (it is a string type).
- All new production code lives under `x/dashboard/` or `x/api/`; wiring changes only in `x/config/` and `gost/cmd/gost/program.go`.
- `Collector.Observe` must never block and must always return `nil`; existing callers retry failed batches and would accumulate duplicates.
- `Collector` must **not** implement `io.Closer`: `service.Close()` closes any observer that implements it, and the collector is shared by every service.
- Keys exposed in the snapshot are low-cardinality: `kind + name + service`. Never put client IP, hostname, URL, or domain into an exposed key.
- Handler `StatsEvent` is **per client** (`Client` = client IP). The collector must dedupe by `(service, client)` internally (last-value, so retries are idempotent), bound that map (default 4096 per service, evict least-recently-seen), and never expose the client key. Service totals prefer the service-level event; handler totals are only used when no service-level stats exist (`metadata.enableStats` off), otherwise the two would double-count.
- Phase 0 assumes **cumulative** counters. If `observer.resetTraffic=true`, log a warning; that service's byte values are interval samples, not cumulative, and the contract says so. Do not silently mix the two modes.
- Code comments in English only.
- Run tests per package (`cd x && go test ./dashboard/ ./api/`); workspace-wide wildcard test runs hang here.
- Plans carry per-task Implementation records; commit after each completed task (commit only, never push).

## Review Focus

- **Retry duplicate batches:** the same cumulative `StatsEvent` may arrive twice after an `Observe` error; last-value replacement must keep totals correct.
- **Concurrent Observe/Snapshot:** `Snapshot()` must never race with `Observe`, and must not hand out internal maps.
- **Shared collector lifetime:** services closing must not disable collection for other services.
- **Unknown event types:** external observer plugins warn/drop unknown types; the local collector must ignore them silently and stay compatible.
- **Disabled dashboard:** when disabled, `/dashboard/snapshot` returns 404 and handlers must keep their original nil observer (no extra goroutines).
- **Per-client handler cardinality:** enabling the dashboard turns on handler stats, whose per-client map is already unbounded in `x/internal/util/stats`; the collector bounds its own copy, but Phase 0 does not fix the pre-existing handler map growth. Document this as a known limitation.

## Data Contract

### Node identity

```go
// Key is the stable identity of an observable node.
type Key struct {
    Kind    string // service | chain | hop | node | bypass | admission | hosts | resolver | auther | limiter | router | recorder | ingress | sd
    Name    string
    Service string // empty for shared modules (hosts, resolver, sd, ...)
}
```

Attribution rules:

| Module | Key | Rule |
|---|---|---|
| service | `service/<name>` | service owns it |
| chain / hop / node | `chain/<chain>`, `hop/<hop>`, `node/<node>` | config identity, no service |
| bypass, admission, auther, limiter, router, recorder | `.../<name>` + `Service` | options carry `Service` |
| hosts, resolver, sd | `.../<name>`, `Service=""` | shared; aggregate only, never fake per-service edges |
| ingress | `ingress/<name>` | config identity |

### Event types

Keep the two existing types unchanged (`status` = service state, `stats` = service/handler counters). Add three types for module-level instrumentation in `x/dashboard/event.go`:

```go
const (
    EventModuleStats observer.EventType = "module_stats"
    EventModuleState observer.EventType = "module_state"
    EventModuleError observer.EventType = "module_error"
)

// ModuleStatsEvent is a cumulative snapshot, never a delta.
type ModuleStatsEvent struct {
    Kind, Name, Service string

    Calls, Hits, Misses, Errors uint64
    InputBytes, OutputBytes     uint64
    LatencySumMicros            uint64
    LatencyCount                uint64
}

// ModuleStateEvent reports a discrete state change.
type ModuleStateEvent struct {
    Kind, Name, Service string
    State               string // enabled | disabled | degraded | failed
    Message             string
}

// ModuleErrorEvent is a bounded diagnostic event.
type ModuleErrorEvent struct {
    Kind, Name, Service string
    Message             string
}
```

`ModuleStatsEvent.Type()` returns `EventModuleStats`; `ModuleStateEvent.Type()` returns `EventModuleState`; `ModuleErrorEvent.Type()` returns `EventModuleError`.

### Snapshot JSON

`GET <api-prefix>/dashboard/snapshot` returns the raw object (no gin `Response` envelope) so a static SPA and `curl | jq` both work.

```json
{
  "version": 1,
  "generatedAt": "2026-11-09T12:00:00Z",
  "startedAt": "2026-11-09T10:00:00Z",
  "sampleIntervalSeconds": 5,
  "services": {
    "http-8080": {
      "name": "http-8080",
      "state": "ready",
      "stats": {
        "totalConns": 12, "currentConns": 3,
        "inputBytes": 4096, "outputBytes": 8192, "totalErrs": 1
      },
      "rate": { "inputBytesPerSecond": 0, "outputBytesPerSecond": 0 }
    }
  },
  "modules": [
    {
      "kind": "hosts", "name": "local", "service": "",
      "state": "enabled",
      "stats": {
        "calls": 100, "hits": 90, "misses": 10, "errors": 0,
        "inputBytes": 0, "outputBytes": 0,
        "latencySumMicros": 250000, "latencyCount": 100
      }
    }
  ],
  "chains": {
    "chain-1": {
      "name": "chain-1",
      "hops": [
        { "name": "hop-0", "nodes": [ { "name": "node-0", "state": "ready" } ] }
      ],
      "stats": { "connects": 0, "errors": 0, "connectDurationSumMicros": 0, "connectCount": 0 }
    }
  },
  "events": [
    { "time": "2026-11-09T11:59:58Z", "level": "warn", "kind": "admission", "name": "lan", "service": "http-8080", "message": "client denied" }
  ],
  "history": [
    {
      "time": "2026-11-09T11:59:55Z",
      "services": { "http-8080": { "currentConns": 3, "inputBytes": 4096, "outputBytes": 8192 } }
    }
  ]
}
```

Phase 0 does not emit topology edges. The frontend merges `/config` (services/chains/hops/nodes) with `snapshot.services` / `snapshot.modules` by `Key`. This keeps the snapshot a pure metrics read model and avoids duplicating config runtime state.

---

## File Structure

```
x/dashboard/
  event.go          event types + Type() methods (module events)
  collector.go      Collector: Observe, registration of series, sampling, Enable/Default
  snapshot.go       Snapshot / node DTOs + deep-copy builder
  history.go        bounded ring for samples and events
  multi.go          observer.Multi fan-out used by default attach
  collector_test.go
  snapshot_test.go
  multi_test.go
x/api/
  dashboard.go      GET /dashboard/snapshot handler
  dashboard_test.go
x/config/
  config.go         DashboardConfig + Config.Dashboard
x/config/parsing/parser/parser.go
  mergeConfig       carry Dashboard through
x/config/parsing/service/parse.go
  attach dashboard.Wrap around handler/service observer options
gost/cmd/gost/program.go
  dashboard.Enable when cfg.Dashboard.Enabled
```

---

### Task 1: Event contract, collector, bounded rings

**Files:**
- Create: `x/dashboard/event.go`
- Create: `x/dashboard/history.go`
- Create: `x/dashboard/collector.go`
- Create: `x/dashboard/snapshot.go` (DTOs + deep-copy `Snapshot()`; rate computation lands in Task 2)
- Test: `x/dashboard/collector_test.go`

**Interfaces:**
- Consumes: `github.com/go-gost/core/observer`, `github.com/go-gost/x/observer/stats` (`StatsEvent`), `github.com/go-gost/x/service` (`ServiceEvent`).
- Produces:
  - `type Key struct { Kind, Name, Service string }`
  - `type Snapshot`, `ServiceSnapshot`, `ServiceStats`, `ServiceRate`, `ModuleSnapshot`, `ChainSnapshot`, `EventRecord`, `HistoryPoint`
  - `func NewCollector(opts ...Option) *Collector`
  - `func (c *Collector) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error`
  - `func (c *Collector) Snapshot() Snapshot`
  - `func Enable(bool)`, `func Enabled() bool`, `func Default() *Collector` (singleton, `sync.Once`)
  - `type Option func(*options)`; `HistoryOption(interval time.Duration, size int) Option`; `EventLimitOption(n int) Option`; `ClientLimitOption(n int) Option`; `ClockOption(fn func() time.Time) Option`

Exact DTO shapes:

```go
type Snapshot struct {
    Version               int                        `json:"version"`
    GeneratedAt           time.Time                  `json:"generatedAt"`
    StartedAt             time.Time                  `json:"startedAt"`
    SampleIntervalSeconds int                        `json:"sampleIntervalSeconds"`
    Services              map[string]ServiceSnapshot `json:"services"`
    Modules               []ModuleSnapshot           `json:"modules"`
    Chains                map[string]ChainSnapshot   `json:"chains"`
    Events                []EventRecord              `json:"events"`
    History               []HistoryPoint             `json:"history"`
}

type ServiceSnapshot struct {
    Name  string       `json:"name"`
    State string       `json:"state"`
    Stats ServiceStats `json:"stats"`
    Rate  ServiceRate  `json:"rate"`
}
type ServiceStats struct {
    TotalConns   uint64 `json:"totalConns"`
    CurrentConns uint64 `json:"currentConns"`
    InputBytes   uint64 `json:"inputBytes"`
    OutputBytes  uint64 `json:"outputBytes"`
    TotalErrs    uint64 `json:"totalErrs"`
}
type ServiceRate struct {
    InputBytesPerSecond  float64 `json:"inputBytesPerSecond"`
    OutputBytesPerSecond float64 `json:"outputBytesPerSecond"`
}
type ModuleSnapshot struct {
    Kind    string      `json:"kind"`
    Name    string      `json:"name"`
    Service string      `json:"service,omitempty"`
    State   string      `json:"state,omitempty"`
    Stats   ModuleStats `json:"stats"`
}
type ModuleStats struct {
    Calls             uint64 `json:"calls"`
    Hits              uint64 `json:"hits"`
    Misses            uint64 `json:"misses"`
    Errors            uint64 `json:"errors"`
    InputBytes        uint64 `json:"inputBytes"`
    OutputBytes       uint64 `json:"outputBytes"`
    LatencySumMicros  uint64 `json:"latencySumMicros"`
    LatencyCount      uint64 `json:"latencyCount"`
}
type ChainSnapshot struct {
    Name  string     `json:"name"`
    Hops  []HopSnapshot `json:"hops"`
    Stats ChainStats `json:"stats"`
}
type HopSnapshot struct {
    Name  string         `json:"name"`
    Nodes []NodeSnapshot `json:"nodes"`
}
type NodeSnapshot struct {
    Name  string `json:"name"`
    State string `json:"state,omitempty"`
}
type ChainStats struct {
    Connects                uint64 `json:"connects"`
    Errors                  uint64 `json:"errors"`
    ConnectDurationSumMicros uint64 `json:"connectDurationSumMicros"`
    ConnectCount            uint64 `json:"connectCount"`
}
type EventRecord struct {
    Time    time.Time `json:"time"`
    Level   string    `json:"level"`
    Kind    string    `json:"kind"`
    Name    string    `json:"name"`
    Service string    `json:"service,omitempty"`
    Message string    `json:"message"`
}
type HistoryPoint struct {
    Time     time.Time                 `json:"time"`
    Services map[string]ServiceHistory `json:"services"`
}
type ServiceHistory struct {
    CurrentConns uint64 `json:"currentConns"`
    InputBytes   uint64 `json:"inputBytes"`
    OutputBytes  uint64 `json:"outputBytes"`
}
```

- [ ] **Step 1: Write the failing tests**

`x/dashboard/collector_test.go` must contain these tests:

```go
func TestCollectorStatsEventReplacesCumulativeSnapshot(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    _ = c.Observe(context.Background(), []observer.Event{
        xstats.StatsEvent{Kind: "service", Service: "svc", TotalConns: 10, InputBytes: 100},
        xstats.StatsEvent{Kind: "service", Service: "svc", TotalConns: 10, InputBytes: 100},
    })
    got := c.Snapshot().Services["svc"]
    if got.Stats.TotalConns != 10 || got.Stats.InputBytes != 100 {
        t.Fatalf("duplicate batch double-counted: %+v", got.Stats)
    }
}

func TestCollectorServiceStateEvent(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    _ = c.Observe(context.Background(), []observer.Event{
        service.ServiceEvent{Kind: "service", Service: "svc", State: service.StateReady},
    })
    if got := c.Snapshot().Services["svc"].State; got != "ready" {
        t.Fatalf("state = %q, want ready", got)
    }
}

func TestCollectorModuleStatsUsesKey(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    _ = c.Observe(context.Background(), []observer.Event{
        ModuleStatsEvent{Kind: "bypass", Name: "direct", Service: "svc", Calls: 7, Hits: 5},
    })
    s := c.Snapshot()
    if len(s.Modules) != 1 || s.Modules[0].Stats.Calls != 7 || s.Modules[0].Stats.Hits != 5 {
        t.Fatalf("modules = %+v", s.Modules)
    }
}

func TestCollectorObserveAlwaysReturnsNilAndIgnoresUnknown(t *testing.T) {
    c := NewCollector()
    if err := c.Observe(context.Background(), []observer.Event{unknownEvent{}}); err != nil {
        t.Fatalf("Observe returned %v", err)
    }
}

func TestCollectorEventRingIsBounded(t *testing.T) {
    c := NewCollector(EventLimitOption(2), ClockOption(func() time.Time { return time.Unix(100, 0) }))
    for i := 0; i < 5; i++ {
        _ = c.Observe(context.Background(), []observer.Event{
            ModuleErrorEvent{Kind: "admission", Name: "lan", Service: "svc", Message: "denied"},
        })
    }
    if got := len(c.Snapshot().Events); got != 2 {
        t.Fatalf("events = %d, want 2", got)
    }
}

func TestCollectorHandlerStatsSumAcrossClients(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    _ = c.Observe(context.Background(), []observer.Event{
        xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.1", InputBytes: 100},
        xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.2", InputBytes: 200},
    })
    got := c.Snapshot().Services["svc"].Stats.InputBytes
    if got != 300 {
        t.Fatalf("input bytes = %d, want 300", got)
    }
}

func TestCollectorHandlerStatsRetryIsIdempotent(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    ev := xstats.StatsEvent{Kind: "handler", Service: "svc", Client: "10.0.0.1", InputBytes: 100}
    _ = c.Observe(context.Background(), []observer.Event{ev})
    _ = c.Observe(context.Background(), []observer.Event{ev})
    if got := c.Snapshot().Services["svc"].Stats.InputBytes; got != 100 {
        t.Fatalf("retry double-counted: %d", got)
    }
}

func TestCollectorConcurrentObserveAndSnapshot(t *testing.T) {
    c := NewCollector()
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ {
        wg.Add(2)
        go func(i int) {
            defer wg.Done()
            _ = c.Observe(context.Background(), []observer.Event{
                xstats.StatsEvent{Kind: "handler", Service: "svc", Client: fmt.Sprintf("10.0.0.%d", i), InputBytes: uint64(i)},
            })
        }(i)
        go func() {
            defer wg.Done()
            _ = c.Snapshot()
        }()
    }
    wg.Wait()
}
```

Add `type unknownEvent struct{}` with `Type() observer.EventType { return "unknown" }`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ -run TestCollector -v`
Expected: FAIL because package/type does not exist.

- [ ] **Step 3: Implement the contract**

`event.go`: the three event structs from the Data Contract, with pointer-free fields and `Type()` methods. Import `github.com/go-gost/core/observer` only.

`history.go`: generic bounded ring helpers are unnecessary; implement two concrete rings:

```go
type eventRing struct { buf []EventRecord; next int; full bool }
func (r *eventRing) add(e EventRecord)
func (r *eventRing) list() []EventRecord // oldest first

type historyRing struct { buf []HistoryPoint; next int; full bool }
func (r *historyRing) add(p HistoryPoint)
func (r *historyRing) list() []HistoryPoint // oldest first
```

`collector.go` holds `mu sync.RWMutex`, `start time.Time`, `services map[string]*ServiceSnapshot`, `serviceSeen map[string]bool`, `handlers map[handlerKey]handlerEntry` (`handlerKey{Service, Client}`, `handlerEntry{stats ServiceStats; seen time.Time}`), `modules map[Key]*ModuleSnapshot`, `chains map[string]*ChainSnapshot`, `events eventRing`, and `history historyRing`. `Observe` type-switches on `xstats.StatsEvent`, `service.ServiceEvent`, `ModuleStatsEvent`, `ModuleStateEvent`, `ModuleErrorEvent`; default is ignored.

- `StatsEvent` with `Kind == "service"`: replaces the service snapshot (and marks `serviceSeen[service] = true`). With `Kind == "handler"`: replaces `handlers[{service, client}]` (last value, never sums across batches) and updates that service's `lastSeen` for eviction.
- `Snapshot()` folds handler rows per service with a sum **only when `serviceSeen[service]` is false**; service-level stats win when present.
- When `len(handlers) > clientLimit` for a service, evict least-recently-seen rows first.
- Module errors append an `EventRecord` and bump that module's error count.

`snapshot.go` defines the DTOs with lowercase JSON tags exactly as in the Data Contract. `Collector.Snapshot()` takes `RLock`, deep-copies maps/slices, sorts `Modules` by `(Kind, Service, Name)`, folds handler rows as described, and returns events/history oldest first. `Rate` stays zero until Task 2 adds history sampling.

`Enable`/`Enabled` use an `atomic.Bool`; `Default()` lazily builds one collector with `sync.Once` and is safe to call from every service.

`Option` defaults: history interval 5s, history size 720 (1h), event limit 500, client limit 4096, `time.Now`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ -run TestCollector -v`
Expected: PASS.

- [ ] **Step 5: Run race and vet**

Run: `cd x && go test -race ./dashboard/ -count=1 && go vet ./dashboard/`
Expected: PASS (set `CGO_ENABLED=1` if the race detector is skipped).

- [ ] **Step 6: Commit**

```bash
git -C x add dashboard
git -C x commit -m "feat(dashboard): add observer event contract and collector"
```

**Implementation record:**
- Date/status: 2026-11-09 — complete.
- Repo + commit: `go-gost/x` @ `13398fd` (code); this record follows in a docs-only commit because a commit cannot contain its own SHA.
- Files changed: `x/dashboard/event.go`, `x/dashboard/history.go`, `x/dashboard/snapshot.go`, `x/dashboard/collector.go`, `x/dashboard/collector_test.go`.
- Tests/commands and results: `go test ./dashboard/ -run TestCollector -v` → 8/8 PASS; `go test -race ./dashboard/ -count=1` → PASS; `go vet ./dashboard/` → clean; `gofmt -l dashboard/` → empty.
- Review findings and fixes: none in this task; interface shapes match the brief.
- Deferred items/limitations: `Rate` stays zero until Task 2; `Chains` is reserved and always empty in Phase 0; module events have no producer until Phase 1.

---

### Task 2: Snapshot model and HTTP endpoint

**Files:**
- Modify: `x/dashboard/snapshot.go` (rates + history sampling)
- Create: `x/dashboard/snapshot_test.go`
- Create: `x/api/dashboard.go`
- Test: `x/api/dashboard_test.go`
- Modify: `x/api/api.go` (register route)

**Interfaces:**
- Consumes: `NewCollector`, `Collector.Snapshot`, `dashboard.Enabled`, `dashboard.Default` from Task 1.
- Produces:
  - `Snapshot` gains rate computation (`ServiceRate` from the newest two history points) and `HistoryPoint` sampling.
  - `func getDashboardSnapshot(c *gin.Context)` (unexported handler in package `api`)
  - `GET /dashboard/snapshot` route under the same basic-auth middleware as `/config`.

- [ ] **Step 1: Write the failing tests**

`x/dashboard/snapshot_test.go`:

```go
func TestSnapshotIsDeepCopy(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    _ = c.Observe(context.Background(), []observer.Event{
        xstats.StatsEvent{Kind: "service", Service: "svc", TotalConns: 1},
    })
    snap := c.Snapshot()
    snap.Services["svc"].Stats.TotalConns = 99
    if got := c.Snapshot().Services["svc"].Stats.TotalConns; got != 1 {
        t.Fatalf("Snapshot aliased internal state: got %d", got)
    }
}

func TestSnapshotJSONHasStableKeys(t *testing.T) {
    c := NewCollector(ClockOption(func() time.Time { return time.Unix(100, 0) }))
    b, err := json.Marshal(c.Snapshot())
    if err != nil { t.Fatal(err) }
    for _, key := range []string{`"version"`, `"services"`, `"modules"`, `"chains"`, `"events"`, `"history"`} {
        if !strings.Contains(string(b), key) { t.Fatalf("missing %s in %s", key, b) }
    }
}
```

`x/api/dashboard_test.go` must verify:
- disabled collector → `404`;
- enabled collector with one service event → `200` and body contains `"svc"`;
- auth middleware is applied: a request without credentials returns `401` when an auther is configured.

Use `gin.New()` + `api.Register(r, &api.Options{Auther: stubAuther{}})` to exercise the real route table rather than calling the handler directly. `stubAuther` is a test type implementing `Authenticate(ctx, user, pass string, opts ...auth.Option) (string, bool)` and returning `("", false)`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ ./api/ -run 'TestSnapshot|TestDashboard' -v`
Expected: FAIL because `Snapshot` fields and route are missing.

- [ ] **Step 3: Implement snapshot and handler**

`snapshot.go` gains history sampling inside `Observe` (append one `HistoryPoint` when `now - lastSample >= interval`, evict oldest beyond `historySize`) and `Rate` computation from the newest two history points (0 when fewer than two points exist). The DTOs themselves were created in Task 1.

`api/dashboard.go`:

```go
func getDashboardSnapshot(c *gin.Context) {
    if !dashboard.Enabled() {
        c.Status(http.StatusNotFound)
        return
    }
    c.JSON(http.StatusOK, dashboard.Default().Snapshot())
}
```

Register in `api.Register` next to the config group:

```go
dash := router.Group("/dashboard")
dash.Use(mwBasicAuth(opts.Auther))
dash.GET("/snapshot", getDashboardSnapshot)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ ./api/ -run 'TestSnapshot|TestDashboard' -v`
Expected: PASS.

- [ ] **Step 5: Run full package tests**

Run: `cd x && go test ./dashboard/ ./api/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git -C x add dashboard api
git -C x commit -m "feat(dashboard): expose GET /dashboard/snapshot"
```

**Implementation record:**
- Date/status: _pending_
- Repo + commit: _pending_
- Files changed: _pending_
- Tests/commands and results: _pending_
- Review findings and fixes: _pending_
- Deferred items/limitations: _pending_

---

### Task 3: Config, default attach, and fan-out

**Files:**
- Create: `x/dashboard/multi.go`
- Create: `x/dashboard/multi_test.go`
- Modify: `x/config/config.go` (`DashboardConfig`, `Config.Dashboard`)
- Modify: `x/config/parsing/parser/parser.go` (`mergeConfig`)
- Modify: `x/config/parsing/service/parse.go` (two observer options)
- Modify: `gost/cmd/gost/program.go` (`dashboard.Enable`)
- Test: `x/dashboard/multi_test.go`

**Interfaces:**
- Consumes: `dashboard.Enabled`, `dashboard.Default` from Task 1.
- Produces:
  - `func Wrap(next observer.Observer) observer.Observer` — returns `next` unchanged when the dashboard is disabled; otherwise a fan-out that includes `Default()`.
  - `type DashboardConfig struct { Enabled bool `yaml:",omitempty" json:"enabled,omitempty"` }`

- [ ] **Step 1: Write the failing tests**

`x/dashboard/multi_test.go`:

```go
func TestWrapDisabledReturnsNext(t *testing.T) {
    Enable(false)
    next := &recordingObserver{}
    if got := Wrap(next); got != next {
        t.Fatal("Wrap must return the configured observer unchanged when disabled")
    }
}

func TestWrapEnabledFansOutToCollectorAndNext(t *testing.T) {
    Enable(true)
    defer Enable(false)
    next := &recordingObserver{}
    wrapped := Wrap(next)
    _ = wrapped.Observe(context.Background(), []observer.Event{
        ModuleStatsEvent{Kind: "bypass", Name: "direct", Calls: 1},
    })
    if next.calls != 1 {
        t.Fatalf("next observer calls = %d, want 1", next.calls)
    }
    if len(Default().Snapshot().Modules) != 1 {
        t.Fatal("collector did not receive the event")
    }
}

func TestWrapEnabledWithoutNextDoesNotPanic(t *testing.T) {
    Enable(true)
    defer Enable(false)
    if err := Wrap(nil).Observe(context.Background(), []observer.Event{unknownEvent{}}); err != nil {
        t.Fatal(err)
    }
}
```

Add `recordingObserver` with a `calls int` field.

The two parse call sites are covered by the existing `x/config/parsing/service` tests compiling and passing; the behavior they add is exactly `Wrap`, which the tests above pin.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd x && go test ./dashboard/ -run TestWrap -v`
Expected: FAIL because `Wrap` does not exist.

- [ ] **Step 3: Implement fan-out and config**

`multi.go`:

```go
type multi struct{ observers []observer.Observer }

func Wrap(next observer.Observer) observer.Observer {
    if !Enabled() {
        return next
    }
    c := Default()
    if next == nil {
        return c
    }
    return &multi{observers: []observer.Observer{c, next}}
}

func (m *multi) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
    for _, o := range m.observers {
        if o == nil { continue }
        _ = o.Observe(ctx, events, opts...) // dashboard must not make the batch fail
    }
    return nil
}

func (m *multi) Close() error {
    var errs []error
    for _, o := range m.observers {
        if c, ok := o.(io.Closer); ok {
            if err := c.Close(); err != nil { errs = append(errs, err) }
        }
    }
    return errors.Join(errs...)
}
```

`multi` may implement `Close` because it closes only the configured observer; `Collector` must not implement `io.Closer`.

`config.go`:

```go
type DashboardConfig struct {
    Enabled bool `yaml:",omitempty" json:"enabled,omitempty"`
}
```

Add `Dashboard *DashboardConfig` to `Config`, and carry it through `mergeConfig` with the same override-if-non-nil pattern used for `API`/`Metrics`.

`parse.go`: replace the two observer options with:

```go
handler.ObserverOption(dashboard.Wrap(registry.ObserverRegistry().Get(cfg.Handler.Observer))),
xservice.ObserverOption(dashboard.Wrap(registry.ObserverRegistry().Get(cfg.Observer))),
```

If `observer.resetTraffic` is true in `cfg.Metadata` or `cfg.Handler.Metadata` while the dashboard is enabled, log a warning and leave the collector attached with a documented caveat (Phase 0 does not implement interval semantics). The warning may repeat on reload; that is acceptable.

`gost/cmd/gost/program.go`: add a helper and call it after **both** `config.Set(cfg)` sites (`Start` and `reloadConfig`):

```go
func applyDashboard(cfg *config.Config) {
    dashboard.Enable(cfg.Dashboard != nil && cfg.Dashboard.Enabled)
}
```

Using the boolean form (not only `Enable(true)`) lets a reload turn the dashboard off. Import `github.com/go-gost/x/dashboard`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd x && go test ./dashboard/ ./config/... -count=1`
Expected: PASS.

- [ ] **Step 5: Build the binary**

Run: `cd gost && go build ./cmd/gost`
Expected: exit 0. Remember: a pattern build writes no binary, so use `go build ./cmd/gost`.

- [ ] **Step 6: Commit**

```bash
git -C x add dashboard config
git -C gost add cmd/gost/program.go
git -C x commit -m "feat(dashboard): wire config and default observer attach"
git -C gost commit -m "feat: enable dashboard collector from config"
```

**Implementation record:**
- Date/status: _pending_
- Repo + commit: _pending_
- Files changed: _pending_
- Tests/commands and results: _pending
- Review findings and fixes: _pending
- Deferred items/limitations: _pending_

---

## Phase 0 Non-Goals

- No `x/observe` package and no bypass/admission/hosts/resolver wrappers (Phase 1).
- No chain/node instrumentation beyond what exists (`gost_chain_*` metrics stay Prometheus-only).
- No WebSocket, no history beyond the in-memory 1-hour ring, no persistence, no topology positions.
- No frontend.
- No changes to `core/`.

## Handoff Notes

Sample config (the existing `api` section must be enabled):

```yaml
api:
  addr: :18080
dashboard:
  enabled: true
```

- Enabling the dashboard attaches an observer to every service and handler, which also starts handler-level stats goroutines. That is the intended cost of getting data without new instrumentation; keep it opt-in.
- `x/internal/util/stats` already keeps an unbounded per-client map per handler. The collector bounds its own copy (4096 per service), but the pre-existing map growth is out of scope for Phase 0.
- Phase 1 starts by adding `dashboard.WrapBypass/Admission/Hosts/Resolver` constructors and calling them in `config/parsing/service/parse.go`; the event contract above is the fixed interface for that work.
- The frontend should call `/config` + `/dashboard/snapshot`; the snapshot intentionally does not duplicate topology.
- If the user runs with `observer.resetTraffic=true`, history values are interval samples, not cumulative, until Phase 1 replaces the semantics.
