# GOST Dashboard Phase 4 Design

Date: 2026-11-09
Status: draft

## Intent

Close the two largest remaining observability gaps and remove the current scaling limitation:

1. **Family-filtered `Gather()`** — stop gathering every Prometheus family every 5 s.
2. **Limiter aggregate counters** — show conn/rate/traffic limiter activity per limiter name, without per-key series.

## Goals

- The dashboard's chain gather returns only `gost_chain_errors_total` and `gost_chain_node_connect_duration_seconds`.
- The snapshot exposes aggregate limiter counters per limiter name: attempts, allowed, denied, bytes requested/granted where applicable.
- No per-key limiter series, no unbounded cardinality.
- No new hot-path allocations in the limiter factories; counters are atomic and skipped when the dashboard is disabled.

## Non-Goals

- Quota limiter instrumentation (quota usage is already visible in `/config/services` via `ServiceStatus.Quotas`).
- Per-key limiter series or client-level counters.
- Frontend rendering.
- Release tagging/pushing (separate approval required).

## Anti-Goals

- Wrapping per-key `Limiter` instances per request.
- Adding locks to the limiter hot path.
- Gathering all metric families when only two are needed.

## Approaches

### Family-filtered Gather

- **Option A**: add `xmetrics.GatherFamilies(names ...metrics.MetricName)` that builds a temporary registry with only the selected `CounterVec`/`HistogramVec` and calls `Gather()`.
- **Option B**: hand-roll a `dto.MetricFamily` conversion for the two known families.

Chosen: **A**. It reuses Prometheus's own gather path, is easy to test, and costs one small registry allocation per 5 s tick. `dashboard/chains.go` calls it with the two chain metric names.

### Limiter aggregate counters

- **Option A**: add atomic counters to the limiter implementations (`connLimiter`, `rateLimiter`, `trafficLimiter`); expose `Stats()` and `SetStats(*stats.Stats)`. The dashboard wraps the limiter at registration, attaches a stats pointer, and reads the counters at `Flush` time through a sample callback.
- **Option B**: wrap the per-key `Limiter` returned by `Limiter(key)` and increment counters per call.

Chosen: **A**. It avoids a per-request wrapper allocation and keeps the dashboard out of the hot path. The limiter's own `Allow`/`Wait` adds a few atomics only when a stats pointer is attached.

## Parts

### Family-filtered Gather

- `x/metrics/gather.go`: `GatherFamilies(names ...metrics.MetricName) ([]*dto.MetricFamily, error)`.
- `x/metrics/gather_test.go`: only the requested families are returned.
- `x/dashboard/chains.go`: `chainGatherer` calls `xmetrics.GatherFamilies(...)`.

### Limiter stats

- `x/limiter/stats/stats.go`: `Stats` with atomic `Calls`, `Allowed`, `Denied`, `WaitCalls`, `Requested`, `Granted`.
- `x/limiter/conn`: `connLimiter` and per-key `llimiter` carry a `*stats.Stats`; `Allow` increments when non-nil; `SetStats`/`Stats` exposed.
- `x/limiter/rate`: same for `rateLimiter` and `rlimiter`.
- `x/limiter/traffic`: same for `trafficLimiter` and its per-key `llimiter`; `Wait` records calls/requested/granted.
- `x/dashboard/limiter.go`: `WrapConnLimiter`, `WrapRateLimiter`, `WrapTrafficLimiter`; each attaches a stats pointer and registers a module series with a sample callback.
- `x/dashboard/module.go`: `moduleCounters` gains a `sample func() LimiterStats`; `snapshot()` merges it.
- `x/dashboard/event.go` + `snapshot.go`: `ModuleStatsEvent` and `ModuleStats` gain `Limiter *LimiterStats`.
- `x/dashboard/collector.go`: `Observe` copies `e.Limiter`.
- `x/config/loader/loader.go`: wrap the three limiter types at registration.
- Tests: limiter counter tests per package; dashboard integration tests for each wrapper; race tests.

## Tests

- `TestGatherFamiliesOnlyRequested` — only the requested families are returned.
- `TestConnLimiterStats` / `TestRateLimiterStats` / `TestTrafficLimiterStats` — counters increment only when a stats pointer is attached.
- `TestWrapConnLimiterExposesStats` / `TestWrapRateLimiterExposesStats` / `TestWrapTrafficLimiterExposesStats` — `Flush` shows the counters in the module snapshot.
- Race tests for limiter counters and dashboard sample callbacks.

## Open Questions

- Should `Stats()` be exposed on the `core/limiter` interfaces? No — core changes are forbidden; use the anonymous interface assertion.
- Should the sample callback run at `Flush` (5 s) or at `Snapshot` (on demand)? Flush is chosen; snapshot stays cheap.
- Should the release be part of this phase? No — tagging/pushing needs explicit approval and is a separate step.

## Handoff

- `gost/go.mod` still pins `x v0.28.1`; release requires tagging `x` and bumping `gost` before `GOWORK=off` builds work.
- Limiter stats are per limiter name, not per client; per-key cardinality is intentionally avoided.
