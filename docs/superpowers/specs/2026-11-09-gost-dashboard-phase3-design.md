# GOST Dashboard Phase 3 Design

Date: 2026-11-09
Status: draft

## Intent

Extend the embedded dashboard with two missing read models:

1. **Chain filtering by the current config** — removed chains must not reappear after a reload.
2. **Resolver cache hit/miss/store counters** — operators can see cache effectiveness per resolver.

## Goals

- `/dashboard/snapshot` `chains` contains only chains defined in the current config.
- `/dashboard/snapshot` `modules` includes resolver cache counters per resolver name.
- No new dependencies, no `core/` changes, no hot-path allocations beyond the existing atomic counters.

## Non-Goals

- Limiter aggregate counters (deferred; see Phase 2 Non-Goals).
- Per-key limiter series.
- Per-hop traffic bytes.
- Frontend work.

## Anti-Goals

- Unbounded series or per-client keys.
- Hot-path locks or allocations in the resolver cache or limiter paths.
- Leaking hostnames, credentials, or client addresses into the snapshot.

## Approaches

### Chain filter

- **Option A**: store a filter set on the `Collector`; `ObserveChains` drops chains not in the set. `Apply(cfg)` computes the set from `cfg.Chains` and calls `SetChainFilter`.
- **Option B**: store the set on the `Collector`; `Snapshot` intersects the chain map with it.

Chosen: **A**. `ObserveChains` already replaces the whole map, so filtering there keeps `Snapshot` simple and avoids a second iteration under the read lock.

### Resolver cache stats

- **Option A**: add atomic counters to `resolver_util.Cache`; expose a `Stats()` method on `localResolver`; `WrapResolver` captures a stats reader and stores the latest values in the resolver's `moduleCounters` on each `Resolve` call.
- **Option B**: global package-level counters in `resolver_util`.

Chosen: **A**. Per-resolver attribution matches the existing module keying; global counters would merge all resolvers and make the dashboard misleading.

## Parts

- `x/dashboard/collector.go`: `chainFilter` field; `SetChainFilter`; `ObserveChains` filters; `Reset` clears the filter.
- `x/dashboard/apply.go`: compute chain names from `cfg.Chains`; call `SetChainFilter` after `ResetState`.
- `x/internal/util/resolver/cache.go`: `hits`, `misses`, `stores` atomic counters; `Stats()` method.
- `x/resolver/resolver.go`: `localResolver.Stats()` returns cache stats.
- `x/dashboard/wrap.go`: `resolverWrapper` captures the stats source; on `Resolve`, store the latest cache counters in `moduleCounters`.
- `x/dashboard/module.go`: add `CacheHits`, `CacheMisses`, `CacheStores` to `ModuleStats` and `ModuleStatsEvent`; `snapshot()` includes them.
- `x/dashboard/snapshot.go`: no change if `ModuleSnapshot` embeds `ModuleStats`.

## Tests

- Chain filter: `Apply` with a config containing `chain-0`; `ObserveChains` with `chain-0` and `chain-old`; snapshot contains only `chain-0`. Reload with a config without `chain-0`; the old chain disappears.
- Resolver cache: `Cache.Load` miss/hit, `Store`; `Stats()` returns counts; `WrapResolver` exposes them in `Flush`.
- Race tests for `ObserveChains` and cache stats.

## Open Questions

- Should the chain filter include chains referenced by services but not defined in `cfg.Chains` (for example plugin chains)?
- Should cache stats be reset on reload? New resolver instances start at zero; old ones are discarded.
- Should `stores` be exposed? It indicates cache population and helps cold-start diagnosis.

## Handoff

- Phase 3 does not touch the limiter packages.
- The chain filter relies on `cfg.Chains`; chains created by plugins at runtime will be filtered out unless added to the filter.
