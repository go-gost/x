# GOST Dashboard UI Design (Phase 5)

Date: 2026-11-14
Status: **superseded** — the UI ships in `gost-ui` instead of the `gost` binary.
See `gost-ui/docs/superpowers/specs/2026-11-14-dashboard-design.md`.

## Intent

The dashboard backend (Phases 0–4) exposes `GET /dashboard/snapshot`, but nothing
renders it. Ship a monitoring-only web UI **inside the `gost` binary**, served by
the existing API server, so a stock `gost` deployment has a working dashboard with
no extra container and no separate hosting.

## Goals

- `gost` embeds a compiled single-page UI and serves it at `/ui/` on the API port.
- The UI reads `GET /dashboard/snapshot` every 3 s and renders services, chains,
  modules, events, and a short history.
- `go install github.com/go-gost/gost/cmd/gost@<tag>` produces a binary that already
  contains the UI (no Node toolchain required to install).
- The UI respects the API's existing basic auth and path prefix.
- Small output: target < 150 KB raw / < 60 KB gzip, no chart library.

## Non-Goals

- Config editing, YAML/JSON editing, secret display (covered by `gost-ui`).
- WebSocket/SSE streaming; polling only.
- Persistence, multi-instance aggregation, topology graph editing, saved layouts.
- Reusing cuttle's React Flow layer; the UI is tables + sparklines.
- i18n. English only for the first cut.
- Tagging `x` or bumping `gost/go.mod`; release is a separate approved step.

## Anti-Goals

- Putting SPA assets in `x`: `x` is a library imported by third parties; it must not
  carry a frontend build or a Node toolchain.
- A separate `http.Server` or reverse proxy in `gost` just to host the UI.
- A build-time Node dependency for `go build ./cmd/gost`.

## Placement decision

| Option | Source | Assets | Verdict |
|---|---|---|---|
| x-owned | `x/web` | embed in `x` | Rejected: bloats every downstream import |
| **gost-owned (chosen)** | `gost/web` | embed in `gost` | Single binary, single release |
| standalone | `gost-ui`/new repo | not embedded | Rejected: user must host two things |

Routing lives in `x/api`, and `x/api/service/service.go` owns the `gin.Engine` with
no extension point, so the binary needs a small hook. Two wirings were considered:

- **A (chosen)**: `x/api.Options.UI` + `api/service.UIOption(...)`; `x` owns auth,
  caching, and SPA fallback. ~60 lines in `x`.
- **B**: `gost` stops using `api_service.NewService` and builds its own gin engine.
  Zero `x` change but duplicates listener/shutdown and drifts.

A generic `Register func(*gin.RouterGroup)` hook was rejected: `mwBasicAuth` is
unexported, so `gost` could not reuse the API's auth and would reimplement it.

## Parts

### 1. `x/api`: UI serving (hook A)

`x/api/api.go`:

```go
type UIOptions struct {
    // FS serves the compiled single-page UI. Required.
    FS http.FileSystem
    // Prefix is the mount path; defaults to "/ui".
    Prefix string
}

type Options struct {
    AccessLog  bool
    PathPrefix string
    Auther     auth.Authenticator
    UI         *UIOptions
}
```

New `x/api/ui.go`:

- Mounts `{prefix}/ui` behind the same `mwBasicAuth(opts.Auther)` as `/config` and
  `/dashboard`, so the shell and the data share one credential.
- `GET {prefix}/ui` redirects (302) to `{prefix}/ui/`.
- `GET {prefix}/ui/*filepath` opens the path from `UI.FS`:
  - missing path or directory → serve `index.html` (SPA fallback);
  - existing file → `http.ServeContent` (content type, ranges, mtime);
  - path starting with `assets/` → `Cache-Control: public, max-age=31536000, immutable`;
  - everything else, including `index.html` → `Cache-Control: no-cache`.
- `nil` UI, or `FS == nil`, registers nothing (current behavior preserved).

`x/api/service/service.go`: add `UIOption(*api.UIOptions)` and pass it through.

### 2. `gost`: embedded assets

`gost/web/web.go`:

```go
package web

//go:embed all:dist
var dist embed.FS

// FS returns the compiled UI rooted at dist/.
func FS() http.FileSystem
```

`gost/cmd/gost/program.go`:

```go
s, err := buildApiService(cfg.API) // adds api_service.UIOption(&api.UIOptions{FS: web.FS()})
```

The UI is always served when the API server runs; `dashboard.enabled` still gates
the data endpoint (the UI shows a "dashboard disabled" state on 404).

### 3. `gost/web`: frontend

Vite + React + TypeScript, `base: './'` (works under any API path prefix), no
router, no UI framework, no chart library. Structure:

- `src/api.ts` — snapshot URL derivation and typed fetch:
  `prefix = pathname.slice(0, pathname.indexOf('/ui/'))`, snapshot at
  `${prefix}/dashboard/snapshot`; `AbortController`, 3 s `setInterval`, pause while
  `document.hidden`, keep the last good snapshot and show a stale banner on error.
- `src/types.ts` — mirrors `x/dashboard/snapshot.go` exactly.
- `src/format.ts` — bytes/Bps/duration/percent formatting.
- `src/components/` — `Services`, `Chains`, `Modules`, `Events`, `Sparkline`, `Stat`.
- `src/App.tsx` — header (uptime, version, `generatedAt`, `metricsEnabled`, live dot)
  and client-side tabs; no URL routing.

Screens:

- **Services**: name, state, total/current conns, in/out bytes, in/out Bps, errors.
- **Chains**: per chain, hops → nodes with connects, errors, avg connect latency
  (`connectDurationSumMicros / connectCount`), and node state.
- **Modules**: grouped by kind (`bypass`, `admission`, `hosts`, `resolver`,
  `auther`, `limiter_conn`, `limiter_rate`, `limiter_traffic`) with calls, hits,
  misses, errors, cache hit/miss/store, limiter calls/allowed/denied/bytes.
- **Events**: time, level, kind, name, service, message (newest first).
- **History**: three inline-SVG sparklines over `history[]`: total input Bps, total
  output Bps, total current conns.
- Empty, disabled (404), unauthorized (401), and error states are explicit.

### 4. Build and release

- `gost/web/dist/` is **committed**, so `go build` and `go install` need no Node.
  This is the same trade-off cuttle makes with `internal/admin/dist`.
- `Makefile`: `web` (`npm ci && npm run build`), `web-check` (`build` + `git diff
  --exit-code -- web/dist`).
- `Dockerfile`: add a `node:22-alpine` stage that builds `web/` and copies `dist`
  over `./web/dist` before the Go build, so images are never stale.
- `.github/workflows/web.yml`: on PRs touching `web/**`, `cmd/gost/**`, or
  `x/api/**`, run `npm ci`, `npm run build`, `tsc --noEmit`, `npm test`, and the
  dist drift check.
- goreleaser needs no change: it builds from the committed `dist`.

## Data contract

`GET /dashboard/snapshot` (unchanged) returns `Snapshot`: `version`, `generatedAt`,
`startedAt`, `sampleIntervalSeconds`, `metricsEnabled`, `services`,
`modules[]`, `chains`, `events[]`, `history[]`. The UI treats all counters as
cumulative and derives rates only from `services[].rate` and `history[]` diffs.
`404` means `dashboard.enabled` is off; `401` means the API auther rejected the
request.

## Tests

- `x/api/ui_test.go` (httptest + `fstest.MapFS`): index at `/ui/`, asset served with
  immutable cache, unknown path falls back to index, `/ui` redirects, no UI option
  → 404, auther set → 401 without credentials and 200 with them, custom `PathPrefix`
  yields `{prefix}/ui/`.
- `gost/web/web_test.go`: embedded FS contains `index.html` and opens it.
- Frontend: `tsc --noEmit`, `vitest` unit tests for `format.ts` and the snapshot URL
  derivation, `vite build`.
- Manual: run `gost -C` with `api.addr`, `dashboard.enabled: true`, open `/ui/`.

## Open Questions

- Commit `web/dist`? Chosen yes (needed for `go install`); if rejected, `go install`
  ships a placeholder and the UI only exists in Docker/release artifacts.
- Should the UI be disableable via `api` config? Deferred; the shell is static and
  the data stays behind the auther.
- Basic auth on static assets means the browser prompts before the first paint when
  an auther is configured. Accepted for consistency with `/config`.

## Handoff

- `gost/go.mod` still pins `x v0.28.1`; `GOWORK=off` builds need an `x` tag and a
  `gost` bump, so this phase is developed in place with `go.work`.
- Phase 6 candidates: SSE/WebSocket streaming, persistence, admission `Service`
  attribution, plugin chain/resolver coverage.
