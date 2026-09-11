# Fix go-gost #754 — SIGHUP reload `bind: address already in use`

## Context

On SIGHUP hot-reload, every service that keeps its address logs
`init: listen tcp :PORT: bind: address already in use` and the reload fails
(issue go-gost/gost#754). Root cause: in `x/config/loader/loader.go`,
`register()` parses+binds **all** new services in a loop (each
`service_parser.ParseService(c)` binds its port at `ln.Init()`) **before**
`registerGroup` closes the old services. So new listeners bind while old
listeners are still open → `EADDRINUSE`. This is a regression from commit
`82e7e50`, which reversed the order (previously close-old-first, then parse)
to preserve old services on a *parse* error.

Only **services** bind ports; chains/hops/limiters/etc. don't, so the bug is
services-only.

**Goal (Fix #1):** separate listener **construction** from **binding** so the
reload can: (1) construct+validate all new services **without** binding
(any error here leaves old services running — preserves `82e7e50`'s property),
(2) close all old services (free ports), (3) bind+create+register the new ones.

## Design

Split `ParseService` into `PrepareService` (construct, no bind) + a
`(*PreparedService).Build()` method (bind + `NewService`). Keep `ParseService`
as a thin wrapper so its two other callers (`x/api/config_service.go`
`createService`/`updateService`) are unaffected — both already avoid
self-collision.

### Critical correctness detail — netns

The tcp listener binds with a **plain** `net.ListenConfig{}` (no self-switch,
`listener/tcp/listener.go:54,59`). For `metadata.netns` services, the bind
currently relies on the caller having switched namespaces first via the
`netns.Set` block at `parse.go:206-231`. Since that block wraps **both**
construction (line 235) **and** the bind (line 244) today, moving `ln.Init()`
into `Build()` would otherwise bind in the wrong (origin) namespace.

Resolution: **move the netns switch into `Build()`**, wrapping `ln.Init()`.
Construction (`rf(listenOpts...)`) only stores options — it is namespace-
independent, so `PrepareService` drops the netns block. Listeners that
self-switch (`xnet.ListenConfig`, `internal/net/net.go:51`) are unaffected
(a redundant same-namespace re-switch is harmless). Capture `netnsIn` on the
`PreparedService`.

## File-by-file changes

### 1. `x/config/parsing/service/parse.go`

- Add exported type:
  ```go
  // PreparedService is a service fully constructed (listener+handler built,
  // options assembled, handler.Init'd) but whose listener is NOT yet bound.
  // Build binds the listener and returns a runnable service.Service.
  type PreparedService struct {
      name       string
      ln         listener.Listener
      listenerMD metadata.Metadata
      h          handler.Handler
      netns      string
      log        logger.Logger
      options    []xservice.Option
  }
  ```
- Add `func PrepareService(cfg *config.ServiceConfig) (*PreparedService, error)`:
  the current `ParseService` body with these changes:
  - **Remove** the netns block (current lines 206-231) — no longer needed at
    construction.
  - Construct listener (factory lookup + `rf(listenOpts...)`) as today.
  - Capture `listenerMD := metadata.NewMetadata(cfg.Listener.Metadata)` instead
    of calling `ln.Init`.
  - **Reorder** handler construction (current lines 249-348: handler TLS/auth/
    recorders/routerOpts/handler factory/forwarder/`h.Init()`) to run **before**
    the bind. Safe: none of it depends on a bound listener. This also fixes a
    latent leak where a handler error after `ln.Init` orphans a bound socket.
  - Assemble the `[]xservice.Option` slice (current lines 350-362) here while
    locals are in scope.
  - Return `&PreparedService{...}` (store `netnsIn`).
- Add `func (p *PreparedService) Build() (service.Service, error)`:
  - If `p.netns != ""`: `runtime.LockOSThread()` + `netns.Get`/`GetFromPath`|
    `GetFromName`/`Set` with `defer netns.Set(originNs)` (mirror old 206-231).
  - `p.ln.Init(p.listenerMD)`; on error log `"init: "`, then
    `if c, ok := p.h.(io.Closer); ok { c.Close() }` (avoid orphaned handler
    goroutines), return `nil, err`.
  - `s := xservice.NewService(p.name, p.ln, p.h, p.options...)`; return `s`.
- Refactor `ParseService` to:
  ```go
  func ParseService(cfg *config.ServiceConfig) (service.Service, error) {
      ps, err := PrepareService(cfg)
      if err != nil { return nil, err }
      if ps == nil { return nil, nil }
      return ps.Build()
  }
  ```
- Add `"io"` import (used in `Build` error path). `netns`, `runtime`,
  `strings`, `metadata`, `xservice` already imported.

### 2. `x/config/loader/loader.go`

Replace the services block in `register()` (lines 304-318) with a three-phase
sequence (services are now special-cased away from the generic
`registerGroup` full-swap):

```go
// --- services (special: only group whose Init binds a port) ---
// Phase 1: construct+validate all new services WITHOUT binding; on any
//          error return early (old services untouched).
// Phase 2: close all old services (free ports).
// Phase 3: bind+create+register each prepared service.
{
    type preparedEntry struct {
        name string
        ps   *service_parser.PreparedService
    }
    var prepared []preparedEntry
    for _, c := range cfg.Services {
        ps, err := service_parser.PrepareService(c)
        if err != nil {
            return err
        }
        if ps != nil {
            prepared = append(prepared, preparedEntry{c.Name, ps})
        }
    }

    registerGroup[service.Service](nil, registry.ServiceRegistry()) // Phase 2: close-all

    for _, e := range prepared {                                    // Phase 3
        svc, err := e.ps.Build()
        if err != nil {
            logger.Default().Errorf("service %s: %v", e.name, err) // log+continue
            continue
        }
        if err := registry.ServiceRegistry().Register(e.name, svc); err != nil {
            svc.Close()
            logger.Default().Errorf("service %s: %v", e.name, err)
        }
    }
}
```

Phase 3 partial-failure policy is **log+continue** (aborting would leave all
not-yet-built services down with old already closed). `registerGroup(nil, r)`
is the existing "clear the group" idiom (covered by
`TestRegisterGroup_EmptyEntries_ClearsExisting`). No new imports needed.

### 3. `x/config/loader/loader_test.go`

Add a port-binding stub + reload test that reproduces EADDRINUSE pre-fix:
- `bindingStubListener` (distinct from inert `stubListener`): `Init` does
  `net.Listen("tcp", addr)`, stores the `net.Listener`; `Addr`/`Close` delegate.
- `freeTCPPort(t)` helper: `net.Listen("tcp","127.0.0.1:0")`, read port, close.
- Register the binding factory under a test-only name (e.g. `"tcp-binding-test"`)
  and the existing inert `"auto"` handler stub, with save/restore `t.Cleanup`.
- `TestRegister_ServiceReloadNoCollision`: build a config with one service on a
  fixed free port; call `register()` twice; assert the **second** call returns
  no error and the service stays registered. Before the fix the second call
  returns `EADDRINUSE`. Assert via `strings.Contains(err.Error(), "address
  already in use")` on failure.
- Add `"fmt"`, `"strings"` imports.

## Reused / referenced (no edits)

- `x/registry/registry.go:83` `Unregister` → calls `Close()` (frees ports in
  Phase 2). `registerGroup` (loader.go:101) used as close-all idiom.
- `x/service/service.go:144` `NewService` (inert re: sockets; runs pre-up,
  sets state) and `:344` `Close()` (closes listener/handler/observer).
- `internal/net/net.go:51` `xnet.ListenConfig` self-switches netns (context
  for why moving the netns block to `Build` is safe).

## Verification

```bash
cd /config/workspace/go-gost/x
go build ./...                                    # refactor compiles
go vet ./...
go test ./config/loader/...                       # existing + new test
CGO_ENABLED=1 go test -race ./config/loader/...   # race-clean (per CLAUDE.md)
cd /config/workspace/go-gost && go build ./...     # gost binary still builds
```
The new test must pass after the change and would fail (`EADDRINUSE` on the
second `register()`) if the construct/bind split were reverted.

Optional manual end-to-end: run gost with one TCP service on a fixed port,
`kill -HUP <pid>`, confirm no `address already in use` in the log and the
service keeps serving.

## Risks / notes

- **netns**: resolved by moving the netns switch into `Build` (see Design).
  During implementation, grep to confirm no listener binds in its *constructor*
  (factories should only store options); if one does, it would need separate
  handling. The 4 checked (tcp/udp/tls/ws) bind in `Init`.
- **Bind failure = one service down**: after close-all, a single bind failure
  takes only that service down (log+continue); unavoidable given the fix's
  premise. A joined-error return is a possible follow-up.
- **Pre-existing, orthogonal**: `x/api/config_reload.go` spawns fresh `Serve`
  goroutines for every registered service on each reload — not caused or
  changed by this fix; flagged so it isn't mistaken for a regression.

## Post-implementation (out of plan scope)

After the code lands + builds + tests pass: optionally post the drafted
explanatory comment to issue #754 and/or open a PR (English comment; show to
user before posting per global GitHub-comments rule).
