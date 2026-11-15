# GOST Connection History — Design

Date: 2026-11-15
Status: approved — backend phase; UI consumption scheduled later.
`docs/superpowers/specs/2026-11-14-gost-dashboard-ui-design.md`
(`gost-ui/docs/superpowers/specs/2026-11-14-topology-overview-design.md`).

## Intent

Give the topology overview a per-connection read model, not only aggregates. The
recorder already writes a `HandlerRecorderObject` per connection; today it
contains the dial path only as one flat string (`"node0@10.0.0.1:1080 >
10.0.0.2:1080 > 10.0.0.99:443"`). This document makes that record structured,
and adds an in-process bounded history that the UI reads.

Goal in one line: **every connection lands in a bounded, structured record; the
UI can list them and light up the exact path one connection took.**

## Why now

The dashboard (Phases 0–4) aggregates counters per module/service/node; it is
right for health but cannot answer "which connection used this path, and what
happened to it?" — and the topology graph needs exactly that to highlight one
connection on demand. The recorder pipeline already carries everything needed
to capture a connection; it only needs structure and a consumer.

## Goals

- One structured record per connection: path (hop → node, per-hop timing and
  error), service, bytes, duration, client identity, reason of refusal.
- **Chain/hop/node statistics are collected in-process by the dashboard
  itself**, so every topology value on the graph works with no metrics endpoint
  configured.
- The record is the same `HandlerRecorderObject` already written to every
  configured recorder, so HTTP/Redis/file recorders and the external inspector
  all receive the enrichment for free.
- An **in-process bounded history** (`/dashboard/connections`) works with no
  external infrastructure (no Mongo/Redis/inspector) out of the box.
- The history is capped and memory-bounded; defaults are sane for a busy proxy.
- Privacy: keep the same fields as today's record (`host`, `dst` included) —
  the record was already per-connection in every deployment.
- No changes to the monitoring counters; the module/chain aggregates now read
  only from in-process records, not from Prometheus.

## Non-Goals

- Cross-node aggregation (all GOST instances). That is inspector's job and is
  possible because the enriched record goes out through recorders for free.
- Request-level (HTTP transaction) history beyond what the recorder already
  records. This is connection history, consistent with GOST's unit of work.
- Replacing the recorder or changing its semantics for existing deployments
  (new fields are `omitempty`, all consumers keep working).
- A new storage engine in-process. The history is a ring of recent records;
  persistence, if wanted later, is the recorder + inspector's job.

## Anti-Goals

- Dropping `host`/`dst` from records by default — the existing recorder
  contract stays byte-compatible with consumers.
- Coupling `x/dashboard` to recorder implementations (file/redis/http/plugin):
  the dashboard must not import them.
- Per-connection events in the monitoring `events` ring as a per-connection
  stream; the history ring is its own bounded buffer.
- Re-encoding the path string client-side; the record carries the structure.

## Data available today

### Direct chain/hop/node collection (replaces the Prometheus path)

Motivation: chain/node stats came from `xmetrics.GatherFamilies`
(`gost_chain_errors_total`, `gost_chain_node_connect_duration_seconds`) — only
when a metrics service was configured and only as process-cumulative
counters. Zero-config deployments got nothing, and metrics cannot be relied
on for a real-time graph.

Design:

1. **`x/chain` gains a hook it does not otherwise depend on**:
   `var ChainRecorded = func(chain string, hop int, node string, d time.Duration, err error) {}`.
   The zero value is a no-op; callers do not import `x/dashboard`.
2. `x/chain/route.go:connect()` calls `ChainRecorded` per hop as each connect
   or handshake completes:
   - success → `err == nil`, `d = time.Since(start)`;
   - failure → classify as `resolve` (resolution of `node.Addr` failed),
     `dial` (Transport.Dial failed), or `handshake` (Transport.Handshake
     failed);
   - hop index == node index within the route (each hop contributes exactly one
     node to the flat route list).
   The final target's own dial is outside the chain (`DefaultRoute`) and is not
   recorded as a hop.
3. `x/dashboard.Enable(true)` replaces `chain.ChainRecorded` with the
   collector's recorder; `Enable(false)` restores the no-op. The record path
   is one or two atomic increments plus a store of the node name — no
   allocation on the hot path.
4. Collector keeps per-chain, per-hop, per-node atomic series:

   ```text
   chains map[string]*chainSeries
   chainSeries  { connects, errors, durationSumMicros, connectCount }    // atomic uint64
                { hops  []hopSeries   // fixed size = max hops seen, index = hop
                  hopSeries { connects, errors, durationSumMicros, connectCount } ;
                  nodes map[string]*nodeSeries }
   ```

   Node series are keyed by node name (the chain/hop are known at record time,
   so both keys are available). `ResetState` zeroes the map; `SetChainFilter`
   still filters what `Snapshot()` writes into `chains` and `nodes` (now it
   works even without metrics).
5. `Snapshot()` fills `Hops` and `Nodes` from the in-process series:
   - `Hops[i].Name` carries the hop's node name;
   - `Nodes[i].Name` carries the node name; `State` is never set
     (no node state exists at that layer);
   - `connects` and `connectDurationSumMicros` per node/hop replace the
     Prometheus reads;
   - `connects = connectCount`.
6. Prometheus counters (`gost_chain_errors_total`,
   `gost_chain_node_connect_duration_seconds`) are still written for external
   metrics consumers but are no longer read by the dashboard.
7. `Snapshot.metricsEnabled` stays for API compatibility but is no longer read
   for chains; the UI's "metrics disabled" hint is dropped.
8. Tests: hook called with correct hop index and classification on the three
   failure classes; collector records increment/zero on reset; filter excludes
   unconfigured chains when no metrics are enabled; snapshot contains hops when
   a 2-hop route is dialed successfully.

### Recorder path

- `ro.Route` already contains the flat path (`"node@addr > ... > target"`),
  built in `x/chain/router.go:dial()` from `routePath(route)`: the nodes of the
  selected route, in dial order, plus the resolved IP of the final target.
- Per-hop dial timing and failure are known in `x/chain/route.go:connect()`
  (start/time per node, success vs failure, and the error).
- Chain name is known at the router (`r.options.Chain`).
- `x/ctx` already threads per-request values to the dial path (same mechanism
  used for `ContextWithBuffer`), so the path can be attached to the recorder
  object from anywhere along the dial path.
- Handlers call `session.Finish(ctx, *ro)` in their `defer` when the connection
  closes; this is the single place every protocol funnels through.

## Design

### 1. Structured path in the record

`HandlerRecorderObject` gains two fields (both `omitempty`, JSON):

```ts
// Ordered from first hop to the final node/target dial.
path: [
  { chain, hop, node, addr, connectMs, err? },
  ...
]
```

Each element is one step of the path:

| Field | Meaning |
|---|---|
| `chain` | chain the step was selected from (empty for the final target / direct route) |
| `hop` | 0-based index of the hop within the chain |
| `node` | node name (or empty for the final target step) |
| `addr` | resolved address dialed (after DNS), or the target address |
| `connectMs` | wall-clock milliseconds for resolution+dial+handshake of that step |
| `err` | short classification: `resolve`, `dial`, `handshake`, `forward`, or empty |

The current flat `route` string is untouched and stays for compatibility.

### 2. Threading the path through the dial

The dial path already threads a buffer through the ctx (`ictx.ContextWithBuffer`).
Reuse the same mechanism for a structured path holder:

- `InternalCtx` (ictx) gains `ContextWithPath(ctx, *[]RouteHop)` and
  `PathFromContext(ctx)` — a mutable slice the dial path appends into.
- `chain/router.go` sets the holder in `dial()`: after the resolved address is
  known and the route is selected, one `RouteHop` is reserved per node
  (`chain`, `hop` index, `node`, `addr`).
- `chainRoute.connect()` fills in `connectMs` and a classified `err` for each
  node as it dials/handshakes. Resolve failure of the first node is recorded on
  that node with `err: "resolve"`; dial failure as `"dial"`; handshake as
  `"handshake"`. The final target's own dial/handshake is a separate element
  (`node: ""`, `chain: ""`).
- `DefaultRoute` (direct, no chain) gets exactly one element with the target.

### 3. The record object carries the path to every consumer

`session.Finish` writes `final` to the configured recorder; the structured path
is on `HandlerRecorderObject`, so every existing recorder gets it with no extra
wiring. `recordMode`/`off` semantics are unchanged.

### 4. In-process bounded history (`/dashboard/connections`)

`x/dashboard` (`Collector`) gains a `recent []ConnectionRecord` ring:

- Default cap **1024** records, configured via the `dashboard` section:
  `connections: { limit: 1024 }` — a single number, user-adjustable to the
  instance's needs; `0` disables the ring entirely; absent keeps the default.
- Record type mirrors the recorder: `sid`, `service`, `clientIP`, `remoteAddr`,
  `bytes` in/out, `durationMs`, `chain?`, `path[]`, `err`, `time`, plus the
  `labels` from the request ctx.
- Population happens in `session.Finish` (after the `final` object is complete)
  when `dashboard.Enabled()` — a single funnel for every protocol; no handler
  changes needed.
- History is served via `GET /dashboard/connections?limit=&service=&sid=`,
  **newest first**, with the authed `/dashboard` route group (same face as
  `/dashboard/snapshot`), returning a JSON array of compact records (fields:
  `sid`, `service`, `remote`, `bytes` in/out, `durationMs`, `chain`, `path`,
  `err`, `time`).
- Oldest records are dropped silently; total memory is bounded by the cap.

### 5. What does and does not go through the ring

| Aspect | Ring | Notes |
|---|---|---|
| service, sid, client ip, remote | ✅ | |
| bytes in/out, duration, time | ✅ | |
| path (chain/hop/node/connectMs/err) | ✅ | |
| host, dst (target) | ✅ | same as existing recorder contract |
| module counters, aggregate stats | ❌ | those stay in `Snapshot()` |
| scheme/TLS/http/websocket sub-records | ❌ | out of scope; the record object can grow later if needed |

### 6. API surface & config

- `GET /dashboard/connections?limit=<int>&service=<name>&sid=<id>` — returns the
  ring. `limit` caps at 1000 (default 200). Returns `200 []ConnectionRecord`,
  or 404 when the dashboard is disabled (same contract as `/dashboard/snapshot`).
- `dashboard` top-level section gains `connections: { limit: 1000 }` — a number;
  `0` disables the ring entirely; absent keeps the default.

### 7. UI consumption (out of scope here, captured for the plan)

`gost-ui` gets a "最近连接" section on the Overview page: a table of the recent
records; clicking a row highlights the matching path on the topology graph and
pans to it; an aggregate filter can limit to a single `service`/sid.

## Approaches considered

| Approach | Tradeoff | Verdict |
|---|---|---|
| **Enrich `HandlerRecorderObject` + in-process ring** — records and history from one struct | one code path, every recorder benefits, zero new infra; memory bounded | **chosen** |
| Chain/hop/node stats gathered directly in-process, replacing the Prometheus read | zero-metrics deployments get full chain visibility; counters reset with config reloads | **chosen** |
| Chain/hop/node stats via Prometheus only | requires a metrics service; process-cumulative rows; config filters already exist | **rejected** (kept for external metrics consumers, no longer read by the dashboard) |
| Ship a separate connection-history service (inspector-style) | needs Mongo/Redis; duplicates what recorder already has | rejected for now (external inspector remains possible because records carry the path) |
| Keep ring only in JS/API (query-record from a remote inspector) | requires inspector deployed; no local fallback | rejected |
| Events ring gets one event per connection | blurs stats events with connections; floods the events table | rejected |

## Testing

- `x/chain` route/router: golden-path test asserting the structured path
  produced for a two-hop route (order, chain names, hop indices, per-node
  `connectMs ≥ 0`, error classification on a dial failure).
- `x/chain` `ChainRecorded` hook: called once per hop with the correct index
  and error class (`resolve`/`dial`/`handshake`); the no-op default leaves
  zero overhead outside a dashboard deployment.
- `x/dashboard`: unit tests for ring cap (rollover), `service`/`sid` query
  filters, disabled-dashboard 404, and record copy semantics.
- `x/dashboard` chain series: direct increment without metrics enabled;
  snapshot contains hops and nodes; `ResetState` clears; `SetChainFilter`
  excludes unconfigured chains.
- `session.Finish` funnel tested via existing recorder test cases: the enriched
  record must still serialize identically for the string `route` field.
- `x/api`: integration test for `/dashboard/connections` limit/filter/404.

## Open questions

- Default cap for the in-process ring is confirmed: **1024**, set in the
  `dashboard` section as `connections: { limit: 1024 }`, user-adjustable; `0`
  disables.
- Pre-dial rejections (admission/limiter/rate-limit before Dial) are **recorded**,
  never dropped: `err` carries the reason (`rate limit`, `admission denied`, …)
  and `path` is absent.
- Ordering: this document is the **backend** phase; UI consumption is scheduled
  after it lands.
