# Plan: Make the mux layer pluggable and integrate Yamux

## Context

GOST's tunnel/relay/mux components multiplex streams over a single connection
through `x/internal/util/mux/mux.go`, which currently hard-wraps
`github.com/xtaci/smux`. Research (`x/docs/superpowers/specs/2026-06-08-tunnel-mux-protocol-research.md`)
concluded Yamux is the most viable alternative backend (broad ecosystem adoption,
different flow-control trade-off) and that making the layer pluggable is
straightforward: the `Session` type is only a handful of methods, and all
consumers funnel through two factory functions.

This plan converts the concrete `*mux.Session` into a `mux.Session` interface,
adds a Yamux implementation behind a `mux.type` selector, and threads the
selector through the existing metadata config (defaulting to `smux`, so all
existing deployments are unchanged).

Scope note: SMUX stays the default; we do **not** change per-component SMUX
version defaults (tunnel/mtcp already default to v2; relay/socks stay v1) — the
research spec explicitly forbids changing those to avoid behavior regressions.

## Approach

Rung check: this needs to exist (integration request) → it's a new backend, not
a re-implementation of an existing helper → stdlib/yamux already solve it → the
smallest change that works is an interface split at the existing chokepoint.

Two design decisions worth flagging:

- **Per-site metadata edits, not a shared `mux.ParseConfig` helper.** The 12
  `metadata.go` files already duplicate the same `muxCfg` literal (pre-existing
  debt). A shared helper would centralize the selector but would couple the
  low-level `internal/util/mux` util to `x/metadata` (architectural smell) and
  risk silently changing per-component version defaults. Adding `Type` +
  `MaxStreamWindow` to each existing literal is the minimal, safe change.
- **Drop `NumStreams()` from the new interface.** It has zero callers across the
  whole module; the 3 dialer wrapper `NumStreams` methods become dead code and
  are deleted.

## Changes

### 1. `x/internal/util/mux/mux.go` — core refactor + Yamux backend

- Add imports: `github.com/hashicorp/yamux`, `github.com/go-gost/x/ctx`.
- Extend `Config`:
  ```go
  Type string // "smux" (default) | "yamux"
  MaxStreamWindow int // yamux MaxStreamWindowSize (bytes)
  ```
  (keep all existing SMUX fields).
- Define the interface and rename the concrete SMUX type:
  ```go
  type Session interface {
      GetConn() (net.Conn, error)
      Accept() (net.Conn, error)
      Close() error
      IsClosed() bool
  }
  type smuxSession struct { conn net.Conn; session *smux.Session }
  ```
  Keep the existing `streamConn` shim (exposes `Context()`) unchanged.
- Add a Yamux implementation mirroring the SMUX one, including a `Context()`
  shim so ctx propagation behaves identically:
  ```go
  type yamuxSession struct { conn net.Conn; session *yamux.Session }
  func (s *yamuxSession) GetConn() (net.Conn, error) { return wrapYamux(s.conn, s.session.Open()) }
  func (s *yamuxSession) Accept() (net.Conn, error) { return wrapYamux(s.conn, s.session.Accept()) }
  func (s *yamuxSession) Close() error              { return s.session.Close() }
  func (s *yamuxSession) IsClosed() bool            { return s.session.IsClosed() }
  ```
  `wrapYamux` embeds the `*yamux.Stream` (a full `net.Conn`) and adds
  `Context()` delegating to the original `conn` (same pattern as `streamConn`).
- Branch the factories on `cfg.Type` (empty → `smux`):
  ```go
  func ClientSession(conn net.Conn, cfg *Config) (Session, error) {
      if muxType(cfg) == "yamux" { return newYamuxClientSession(conn, cfg) }
      return newSMUXClientSession(conn, cfg)
  }
  // ServerSession analogous
  ```
- `newYamuxClientSession` / `newYamuxServerSession` build `*yamux.Config` from
  `cfg`, **based on `yamux.DefaultConfig()`** (satisfies `VerifyConfig`'s
  `KeepAliveInterval > 0` / `AcceptBacklog > 0` requirements), overriding only
  when the user supplies a value:
  - `KeepAliveInterval` ← `cfg.KeepAliveInterval` (if > 0)
  - `EnableKeepAlive = false` ← `cfg.KeepAliveDisabled`
  - `MaxStreamWindowSize = uint32(cfg.MaxStreamWindow)` (if > 0; must be ≥ 256 KiB
    or Yamux errors at session creation — acceptable misconfig behavior)

### 2. `x/go.mod` + `x/go.sum` — add dependency

Run `cd x && go get github.com/hashicorp/yamux@v0.1.1 && go mod tidy`.
(Yamux has no heavy deps; `go mod tidy` resolves it.)

### 3. The 12 `metadata.go` files — add the selector to the muxCfg literal

In each, add two fields to the existing `&mux.Config{...}` literal
(keep all 7 existing keys + post-hoc `Version`/`MaxStreamBuffer` overrides):

```go
Type:           mdutil.GetString(md, "mux.type"),
MaxStreamWindow: mdutil.GetInt(md, "mux.maxStreamWindow"),
```

Files (the `muxCfg = &mux.Config{...}` site in each):
- `handler/tunnel/metadata.go`
- `handler/relay/metadata.go`
- `handler/socks/v5/metadata.go`
- `connector/relay/metadata.go`
- `connector/socks/v5/metadata.go`
- `connector/tunnel/metadata.go`
- `dialer/mtcp/metadata.go`
- `dialer/mws/metadata.go`
- `dialer/mtls/metadata.go`
- `listener/mtcp/metadata.go`
- `listener/mws/metadata.go`
- `listener/mtls/metadata.go`

### 4. Consumer type-reference flips `*mux.Session` → `mux.Session`

Mechanical: change the stored field / constructor param from pointer to
interface value (all already produce values that satisfy the interface):

- `connector/relay/listener.go` — `bindListener.session`
- `connector/socks/v5/listener.go` — `tcpMuxListener.session`
- `connector/tunnel/listener.go` — `bindListener.session`
- `dialer/mtcp/conn.go`, `dialer/mws/conn.go`, `dialer/mtls/conn.go` —
  `muxSession.session` **and delete the now-dead `NumStreams()` method** (zero callers)
- `handler/relay/entrypoint.go` — `tcpHandler.session` field + `newTCPHandler` param
- `handler/tunnel/connector.go` — `Connector.s` field + `NewConnector` param

### 5. Test files (keep them compiling)

`x/` has no test convention but these compile during `go vet`:
- `handler/tunnel/tunnel_test.go` — `newTestSession` return type and
  `newTestConnector` param: `*mux.Session` → `mux.Session`.
- `handler/tunnel/bind_test.go` — `muxCfg: &mux.Config{Version: 2}` literals are
  unaffected (still `*mux.Config`); no change needed unless a `*mux.Session`
  reference appears.

## Critical files

| File | Change |
|------|--------|
| `x/internal/util/mux/mux.go` | Interface + SMUX rename + Yamux backend + dispatch |
| `x/go.mod`, `x/go.sum` | Add `hashicorp/yamux` |
| 12 × `*/metadata.go` | Add `Type` + `MaxStreamWindow` to `muxCfg` |
| 8 consumer files (§4) | `*mux.Session` → `mux.Session` |
| `handler/tunnel/*_test.go` | Update session type refs |

## Verification

1. `cd x && go build ./...` — compiles (incl. all consumer/metadata changes).
2. `cd x && go vet ./...` — static analysis + compiles test files.
3. Optional smoke test: build the gost binary and run a tunnel pair where the
   tunnel handler/service carries `metadata: { mux.type: yamux }`; confirm the
   session establishes and streams flow. (Full e2e suite needs Docker; not
   required for this change.)

## Out of scope (deferred)

- Shared `mux.ParseConfig(md)` helper to de-duplicate the 12 literals — would
  couple low-level `internal/util/mux` to `x/metadata`; do it only as part of a
  broader config-normalization pass.
- QUIC-based multiplexing — already handled at the listener/dialer level
  (`http3`), not a mux-plugin concern.
