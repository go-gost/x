# GOST Connection History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give GOST a real-time, per-connection read model: direct chain/hop/node counters in the dashboard (no metrics dependency), an enriched per-connection recorder record (structured path), and an in-process bounded connection history exposed at `/dashboard/connections`.

**Architecture:** Extend `x/chain` with a zero-dependency `ChainRecorded` hook; `x/dashboard` collects chain/hop/node counters in-process (replacing the Prometheus read). Extend the recorder record with a structured `path` written for free by the dial path via the existing recorder-object ctx mechanism; persist the last N records in a bounded ring inside the dashboard collector; expose by authed route.

**Tech Stack:** Go (x module), Go 1.x upstream, go test.

**Spec:** `docs/superpowers/specs/2026-11-15-connection-history-design.md`

## Global Constraints

- No dependency on a metrics service for chain/hop/node dashboards; `snapshot.metricsEnabled` stays informational only.
- No external garbage-collector tricks; no new module dependencies in `core/` (untouched).
- `HandlerRecorderObject` gains fields only with `omitempty`; `route` string behaviour unchanged (inspectors/recorders keep working).
- `session.Finish` remains the single funnel — no protocol handler required to change.
- Connection ring defaults to 1024, configurable (`dashboard.connections.limit`), `0` disables, absent keeps 1024.
- Pre-dial refusals (admission/rate limit) are recorded with `err` set and no `path`.
- Privacy: keep the same fields as today's records (`host`, `dst` included).
- The UI (gost-ui) is out of scope; this phase is backend-only.
- Commit per task; the spec's UI consumer phase will re-read `/dashboard/connections`.

## Review Focus

- **Hop index order vs route build order** — the test must assert hop indices run `0,1,...,n` in dial order even with multiplex splits.
- **resolve failures must count as node errors** but not produce `connectDurationSumMicros`; the UI divides by connectCount and expects errors to be non-fatal to stats.
- **A connection rejected before Dial** (rate limit/admission) must appear in the history as a record with `err` and no `path`, never be silently dropped.
- **Ring overflow** — the oldest record must be evicted and `service`/`sid` filtering must still be consistent after wrap-around.
- **`route` string format must not drift** — recorder output must serialize unchanged for legacy consumers; only the new `path` field may appear.
- **Reset on reload** — `ResetState` must zero the ring and chain series, otherwise a config reload resurrects stale node rows.

---

### Task 1: Direct chain/hop/node collection

**Files:**
- Create: `chain/record.go` (hook)
- Modify: `chain/route.go` (record success/failure per hop)
- Create: `dashboard/chains.go` (replacement of old chains.go)
- Delete: old `dashboard/chains.go` prometheus gather path and `dashboard/collect_chains*`; adjust `dashboard/apply.go` (drop `ObserveChains` wire), `dashboard/collector.go` (drop `ObserveChains` field/method)
- Modify: `dashboard/collector.go#Snapshot` (fill hops/nodes from series)
- Test: `chain/route_test.go` (add golden path tests), `dashboard/chains_test.go` (replace)
- Check (no change expected): `dashboard/collector_test.go` (filter tests adapt), `x/api` (nothing yet)

**Interfaces:**
- Consumes: `chainRoute` internal fields, `r.options.Chain`.
- Produces:

```go
// chain/record.go — zero-dependency hook, default no-op
package chain

var ChainRecorded = func(chainName string, hop int, node string, d time.Duration, err error) {}
// err is nil on success (d measured); on failure d is still the elapsed time.
// Error class: "resolve" | "dial" | "handshake".

// dashboard/chains.go — replaces the Prometheus gather
type chainSeries struct { name string; connects, errors, durationSumMicros, connectCount uint64; hops []hopSeries; nodes map[string]*nodeSeries }

// snap: hops (size = config chain hop count) with node name on each hop, nodes by name.
func (c *Collector) chainSeriesLocked(chainName string) *chainSeries
func (c *Collector) recordChainHop(chainName string, hop int, node string, d microseconds uint64, err error)
```

- [ ] **Step 1: Write the failing test for `hop index == node index` and error classification in route.go**

Add to `chain/route_test.go` a test `TestConnectTwoHopsRecordsHopSequence` that runs a 2-hop route with a synthetic `chain.Node` set (one of each, `MarkAddrFailed`? instead use a local route) and asserts the `ChainRecorded` sequence is `[hop0 ok, hop1 ok]` in order with non-zero durations and nil errors.

Also `TestConnectResolveFailureRecordsResolve` — node with an unresolvable address (e.g. `""`) → `ChainRecorded` called with `err != nil` and message containing `resolve`; `d` may be zero.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./chain/ -run 'TestConnect.*Records' -v`
Expected: FAIL — `ChainRecorded` undefined / hook not called.

- [ ] **Step 3: Implement the hook and call sites**

In `chain/record.go` define the hook. In `route.go`:
- resolve failure of node i (first node): `ChainRecorded(name, i, node.Name, 0, fmt.Errorf("resolve: %w", err))` before returning;
- `observeNodeConnectDuration` increments at the existing two success calls (hop0 first-node and subsequent hops) — add `ChainRecorded(name, hopIndex, node.Name, d, nil)` next to them;
- node handshake/dial failure for node i: classify (`resolve` if ResolveAll returned error, `dial` if Transport.Dial, `handshake` otherwise) and `ChainRecorded(name, i, node.Name, 0, fmt.Errorf("%s: %w", class, err))` just before returning.

Track hop index (`var hopIndex int` increments per iteration in the loop after the first node, which is index 0; first node is hop 0).

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./chain/ -v -run 'TestConnect.*Records'`
Expected: 2 passed.

- [ ] **Step 5: Rewrite `dashboard/chains.go` around direct collection**

Delete the Prometheus gather body. Implement `chainSeries` with `sync.Map` or a `map` guarded by the collector's `mu`; counters via `atomic.Uint64` (stdlib, Go ≥ 1.19). `Collector.recordChainHop(...)` updates:
- chain: `connects`/`connectCount` (success) or `errors` (failure); `durationSumMicros += d` only on success or both? per metrics behaviour: histograms saw success only, errors counter saw failure. **Rule: only success increments `connects` and `durationSumMicros`; failure increments `errors` only.**
- hop entry (bounded by `len(chain.Hops())` — the chain from `name` argument matches a known hop index; index out of range → record directly on chain level but mark node) — node series keyed by node name.

- [ ] **Step 6: Wire into Enable/ResetState**

`Enable(true)` sets `chain.ChainRecorded` to `c.recordChainHop`; `Enable(false)` resets to no-op. `ResetState()` zeroes `chainSeries`. Drop `chainFilter` handling of Prometheus: filter stays for snapshot output (match configured chains when `cfg.Chains` non-empty), applied when writing `snap.Chains`.

- [ ] **Step 7: Rewrite chain filter tests and run**

`go test ./dashboard/ -run 'Route|Chain|Reset' -v` — existing `chains_test.go` replaced with direct-count assertions; `apply_test.go` should still pass (metrics disabled → chains now present when counters exist — update fixture expectations).

- [ ] **Step 8: Commit**

```bash
git add chain/record.go chain/route.go chain/route_test.go dashboard/chains.go dashboard/chains_test.go dashboard/apply.go dashboard/collector.go
git commit -m "feat(dashboard): collect chain/hop/node counters in-process"
```

---

### Task 2: Structured path in the recorder

**Files:**
- Modify: `recorder/recorder.go` — add `Path []PathHop`, `Chain string`
- Modify: `recorder/session_record.go` — copy Path/Chain from HandlerRecorderObject (it is the same struct via `HandlerRecorderObject`, so just add fields to it — no code needed in `SessionRecorder`)
- Modify: `chain/route.go` — fill Path via `ictx.RecorderObjectFromContext(ctx)`
- Test: `recorder/recorder_test.go` (golden serialization), `chain/route_test.go`
- Modify: `ictx` is untouched (reuses `RecorderObjectFromContext`)

**Interfaces:**
- Consumes: `HandlerRecorderObject`, `ictx.RecorderObjectFromContext`, `ChainRecorded`
- Produces:

```go
type PathHop struct {
    Chain      string `json:"chain,omitempty"`
    Hop        int    `json:"hop"`
    Node       string `json:"node"`
    Addr       string `json:"addr"`
    ConnectMs  uint64 `json:"connectMs"`
    Err        string `json:"err,omitempty"`   // "resolve" | "dial" | "handshake" | ""
}
```

- [ ] **Step 1: Write the failing golden serialization test**

In `recorder/recorder_test.go`, a test `TestHandlerRecorderObjectSerializesPath`: constructs an object with one hop (`chain=c1, hop=0, node=n1, addr=10.0.0.1:80, connectMs=3`), marshals, unmarshals, and asserts the `path` key exists with exactly those values and the `route` key round-trips unchanged.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./recorder/ -run SerializesPath -v`
Expected: FAIL — `path` key absent.

- [ ] **Step 3: Add `Path` and `Chain` to HandlerRecorderObject**

Add after `Retries`:

```go
Chain string    `json:"chain,omitempty"`
Path  []PathHop `json:"path,omitempty"`
```

Add `PathHop` type with json tags above. Re-run recorder tests — existing snapshots must be unchanged (new keys omitempty).

- [ ] **Step 4: Populate `path` during Dial**

In `route.go`, in the same two spots as `ChainRecorded`:
- success of hop: `if ro := ictx.RecorderObjectFromContext(ctx); ro != nil { ro.Path = append(ro.Path, PathHop{... connectMs ms, …}) }`;
- failure: set the terminal `PathHop` with `err` classification and append, then return early;
- set `ro.Chain` once per route: after `route := options.Chain.Route(ctx, ...)` or when `nil` (`""` chain), set `ro.Chain = chainName` — guard `ro == nil`.

Rejected/no-dial connections leave `path` unset — they surface as `err`-only records.

- [ ] **Step 5: Run all recorder + chain tests**

Run: `go test ./recorder/ ./chain/ -v -run 'SerializesPath|Records'`
Expected: all pass; no existing failures newly introduced.

- [ ] **Step 6: Commit**

```bash
git add recorder/recorder.go recorder/recorder_test.go chain/route.go chain/route_test.go
git commit -m "feat(recorder): structured path in connection records"
```

---

### Task 3: Bounded in-process connection ring

**Files:**
- Create: `dashboard/connections.go` (ring + types + filter)
- Modify: `dashboard/collector.go` (`history []ConnectionRecord`, `connectionsLimit`, `Connections(limit int, service, sid string) []ConnectionRecord`, `RecordConnection(rec ConnectionRecord)`)
- Modify: `dashboard/apply.go` (pass `cfg.Dashboard.Connections.Limit` to `Enable`; default 1024 when unset)
- Modify: `config/config.go` — `DashboardConfig` gains `Connections *ConnectionsConfig` (`Limit int`)
- Modify: `recorder/session.go` (`Finish`: after building `final`, if `dashboard.Enabled()` call `dashboard.Default().RecordConnection(copyOf(final))`)
- Test: `dashboard/connections_test.go` (cap, eviction, filters), `dashboard/collector_test.go` (wrap-around sanity)

**Interfaces:**
- Produces:

```go
// ConnectionRecord — public read model for the UI
type ConnectionRecord struct {
    SID        string     `json:"sid"`
    Service    string     `json:"service"`
    ClientIP   string     `json:"clientIP,omitempty"`
    RemoteAddr string     `json:"remoteAddr"`
    BytesIn    uint64     `json:"bytesIn"`
    BytesOut   uint64     `json:"bytesOut"`
    DurationMs uint64     `json:"durationMs"`
    Chain      string     `json:"chain,omitempty"`
    Path       []PathHop  `json:"path"`
    Err        string     `json:"err,omitempty"`
    Time       string     `json:"time"`
    Labels     map[string]string `json:"labels,omitempty"`
}
func (c *Collector) Connections(limit int, service, sid string) []ConnectionRecord
func (c *Collector) RecordConnection(rec ConnectionRecord)
```

- [ ] **Step 1: Write ring unit test**

In `dashboard/connections_test.go`: `TestRingEvictsOldest` writes cap+2 records and asserts the first two are gone; `TestConnectionsFilterByServiceSid` writes 3 records and filters by service/sid; `TestConnectionsDefaultCap` enables with nil config → 1024 enforced.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./dashboard/ -run 'TestRing|TestConnections' -v`
Expected: FAIL — undefined types.

- [ ] **Step 3: Implement the ring**

Fixed-capacity slice wired into `Collector`, indexed by an atomic counter; eviction is `c.history = append(c.history, rec); if len > limit { drop oldest }`. `Connections(limit, service, sid)` walks newest-first, applying filters, returning at most `limit` rows. `RecordConnection` copies the record (path slice cloned) so later mutation by the handler doesn't corrupt the ring.

- [ ] **Step 4: Add config and wire `Enable/ResetState`**

`config.go`: `Connections *ConnectionsConfig` with `Limit int`. `Apply` reads it and passes into collector state; `ResetState` clears the ring and counts.

- [ ] **Step 5: Funnel `session.Finish`**

In `recorder/session.go#Finish`, after `final` is built, if `dashboard.Enabled()`: copy to `dashboard.ConnectionRecord{...}` and `dashboard.Default().RecordConnection(...)`. Never block, never return error.

- [ ] **Step 6: Run all dashboard tests**

Run: `go test ./dashboard/ ./config/ ./recorder/ -count=1 -timeout=2m`
Expected: all pass (previous filter tests updated for new chain path; any fixture touching `chains` must now see in-process rows).

- [ ] **Step 7: Commit**

```bash
git add dashboard/collector.go dashboard/connections.go dashboard/apply.go dashboard/connections_test.go config/config.go recorder/session.go
git commit -m "feat(dashboard): bounded in-process connection history ring"
```

---

### Task 4: `/dashboard/connections` API

**Files:**
- Modify: `api/dashboard.go` (add `getDashboardConnections`)
- Modify: `api/api.go` (`dash.GET("/connections")`)
- Modify: `api/dashboard_test.go` (or create) — integration tests

**Interfaces:**
- Consumes: `dashboard.Default().Connections(limit int, service, sid string)`
- Produces: `GET /dashboard/connections?service=&sid=&limit=` → `200 []ConnectionRecord` | `404` (dashboard disabled) | `400` for limit > 1000.

- [ ] **Step 1: Write the failing integration test**

```go
func TestGetConnectionsReturnsRingNewestFirst(t *testing.T) { ... }
func TestGetConnectionsFiltersByService(t *testing.T) { ... }
func TestGetConnections404WhenDisabled(t *testing.T) { ... }
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./api/ -run Connections -v`
Expected: FAIL — 404 route not registered.

- [ ] **Step 3: Implement endpoint**

Register next to `/snapshot`; parse `service`, `sid`, `limit` (default 200, cap 1000); call `Connections`; write JSON. 404 when dashboard disabled, consistent with `/snapshot`.

- [ ] **Step 4: Run and verify**

Run: `go test ./api/ -run Connections -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add api/dashboard.go api/api.go api/dashboard_test.go
git commit -m "feat(api): expose /dashboard/connections"
```

---

## Implementation records

Fill one subsection per task after it is complete, then include it in that task's commit.

### Task 1
- Date/status: 2026-11-15 — complete
- Repository + commit SHA: x @ (this commit)
- Files changed: `chain/record.go` (new hook), `chain/route.go` (hop records with success/failure classification), `chain/route_test.go` (2 golden tests), `dashboard/chains.go` (rewrite: in-process connectSeries keyed per chain/hop/node), `dashboard/chains_test.go` (rewrite), `dashboard/collector.go` (`chains map[string]*chainSeries`, snapshot via `chainsLocked`, `Enable` swaps the hook), `dashboard/module.go` (drop Prometheus `CollectChainStats`), `dashboard/apply_test.go` / `collector_test.go` (ObserveChains → recordChainHop), `dashboard/chains_test.go`.
- Tests/commands and results: `go test ./chain/ ./dashboard/ -count=1` → ok; `go vet ./chain/ ./dashboard/ ./recorder/` → clean; `go test ./chain/ -run 'TestConnect.*Records' -v` → 2 passed.
- Review findings and fixes: `xmetrics` remains imported in dashboard/collector.go for the informational `metricsEnabled` flag only; the chain series no longer read Prometheus, so metrics is no longer required for chain/node visibility.
- Deferred items/limitations: hop node state is never set; metrics service remains optional for external Prometheus consumers.

### Task 2
- Date/status: 2026-11-15 — complete
- Repository + commit SHA: x @ (this commit)
- Files changed: `recorder/recorder.go` (new `PathHop`, `Path`, `Chain` omitempty fields), `chain/route.go` (populate Path on every hop success/failure, incl. first-hop dial/handshake/resolve), `chain/record.go` (helpers `recordChainName`, `recordPath`, `hopMs`), `recorder/recorder_test.go` (golden round trip), `chain/route_test.go` (`TestConnectRecordsPathOnRecorder`).
- Tests/commands and results: `go test ./recorder/ ./chain/ -count=1` → ok (8.9s / 2.4s); `go build ./chain/` clean.
- Review findings and fixes: `Path` reuses the same `RecorderObjectFromContext` ctx path as `Route`, so all dialed hops emit structured records with zero change to handlers; pre-dial refusals remain on the `err`-only record with absent `Path`.
- Deferred items/limitations: long-lived connections never refresh Path, it reflects the dial path only (as intended).

### Task 3
- Date/status:
- Repository + commit SHA:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

### Task 4
- Date/status:
- Repository + commit SHA:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:
