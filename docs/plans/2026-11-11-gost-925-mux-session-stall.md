# gost#925: Mux Session Stall Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a multiplexed tunnel (`relay+mtls` and friends) recover on its own when its send path stops draining, instead of staying "open" forever and failing every new connection with smux `timeout`.

**Architecture:** Two independent mechanisms in `x/internal/util/mux`, then the same two changes applied in the dialers that own the session maps. (A) A stream write that times out is a *session-level* failure — two of them with no successful write in between close the session, so its owner retires and rebuilds it. (B) `GetConn` honours the caller's context and a `mux.openTimeout` backstop, and neither the TCP dial nor the stream open runs under `sessionMutex`.

**Tech Stack:** Go (x module), `github.com/xtaci/smux v1.5.57`, `github.com/hashicorp/yamux v0.1.1`, standard `testing`.

**Spec:** `x/docs/superpowers/specs/2026-11-11-gost-925-mux-session-stall-design.md`

## Global Constraints

- Do **not** modify `core/`; all changes stay in `x/`.
- Code comments in English only.
- The observed failure signature is smux `ErrTimeout` (`Error() == "timeout"`) from `stream.Write` with a blocked send path, while `Session.IsClosed()` stays `false` and the peer keeps sending frames. Both mechanisms below exist to close that gap; do not weaken either to "log and continue".
- A session is closed, never repaired: recovery comes from the dialer rebuilding it on the next `Dial`/`Handshake`.
- `GetConn()` keeps its signature and delegates to `GetConnContext(context.Background())`; only dialers (not listeners) pass a context. `Accept()` is never bounded.
- Default `mux.openTimeout` is 15s (`defaultOpenTimeout`), matching `chain.Router`'s default dial timeout.
- Sessions are keyed by the address `Dial` was called with; do not change the key.
- Tests run per package (`go test ./internal/util/mux/`, `go test ./dialer/mtls/`, ...); never wildcard.
- Plans carry per-task Implementation records; commit after each completed task (commit only, never push).

## Review Focus

- **False positives:** two write timeouts with a *successful* write between them must not close the session; a non-timeout write error must not close it either.
- **Deadlock/leak:** abandoning a timed-out open must not leak the stream it eventually produces, and `GetConnContext` must return even when the underlying open never returns.
- **Convergence:** two `Dial`+`Handshake` pairs racing for the same address must still end on one session (the behaviour fixed by `6911ecd`).
- **Fast path cost:** a live session must still be returned from `Dial` without any network I/O, and without waiting behind another goroutine's slow dial.
- **Server side:** the same guard runs on `Accept()`ed streams; closing the session there must not disturb the listener's accept loop beyond the session it belongs to.

---

## File Structure

```
x/internal/util/mux/
  mux.go            Session interface + Config; smux/yamux sessions; sessionStall; stream conns
  mux_test.go       stall guard, OpenTimeout, context-bound open tests
x/dialer/mtls/
  dialer.go         Dial: fast path under lock, TCP dial outside; Handshake: open outside lock
  metadata.go       mux.openTimeout wiring
  dialer_test.go    concurrent-dial, rebuild-after-close tests
x/dialer/mtcp/
  dialer.go         same as mtls
  metadata.go       same as mtls
  dialer_test.go    same as mtls
x/dialer/mws/
  dialer.go         same as mtls (plus the websocket-specific initSession call)
  metadata.go       same as mtls
  dialer_test.go    same as mtls
x/docs/superpowers/specs/2026-11-11-gost-925-mux-session-stall-design.md
                    design + evidence write-up (the spec this plan implements)
```

---

### Task 1: Close a mux session whose stream writes stop draining

**Files:**
- Modify: `x/internal/util/mux/mux.go`
- Test: `x/internal/util/mux/mux_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: unexported `sessionStall` with `observe(err error)`; `smuxSession`/`yamuxSession` gain a `stall *sessionStall` field; `streamConn`/`yamuxStreamConn` gain a `stall *sessionStall` field. Tasks 2–4 rely on `streamConn.stall` being non-nil for every conn returned by `GetConn`/`Accept`.

- [ ] **Step 1: Write the failing tests**

In `mux_test.go`, add the `stallConn` helper and the three tests below. `stallConn` must delegate everything to the embedded `net.Conn` and only block inside `Write` while `blocked` is set; `release` is closed by the test's cleanup so the blocked goroutine exits.

```go
// smux returns ErrTimeout from a stream write when the frame never reaches
// the socket; the session itself stays usable, so only an explicit close can
// make the owner rebuild the tunnel. Two in a row, with no successful write
// in between, mean the send path is gone.
func TestSessionClosesAfterRepeatedWriteTimeouts(t *testing.T)  // smux backend, Version 2

// A single timed-out write must not condemn the session.
func TestSessionSurvivesSingleWriteTimeout(t *testing.T)        // smux backend, Version 2

// yamux reports a stalled connection immediately and then blocks the next
// write forever, so its error is final on the first occurrence.
func TestYamuxSessionClosesOnConnectionWriteTimeout(t *testing.T)
```

Each test: `net.Pipe()`, wrap the client end in `stallConn`, create server and client sessions from the two ends, open one stream, accept it on the server (in a goroutine), then:

1. `stallConn.setBlocked(true)`, `stream.SetWriteDeadline(time.Now().Add(300*time.Millisecond))`, `stream.Write(make([]byte, 1024))` → expect a non-nil error.
2. For the "closes" cases, repeat step 1 and then require `cli.IsClosed()` within 1s (poll with a 10ms ticker; do not `time.Sleep` a fixed duration).
3. For `TestSessionSurvivesSingleWriteTimeout`: after the first timeout, `setBlocked(false)`, write 4 bytes and read them back through the server stream (expect the echo), then block again and time out once — `cli.IsClosed()` must still be `false`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd x && go test ./internal/util/mux/ -run 'TestSessionCloses|TestSessionSurvives|TestYamuxSessionCloses' -count=1 -timeout 60s`
Expected: FAIL — `IsClosed()` stays false after the timeouts.

- [ ] **Step 3: Implement `sessionStall` and wire it into both backends in `mux.go`**

```go
// sessionStall watches a session's send path. A stream write that times out
// means its frame never reached the socket, and nothing else notices: the
// session's keepalive only tracks received frames, so a peer that keeps
// sending while it stops reading leaves the session "open" forever and every
// new stream stalls on it. Closing the session is the only signal its owner
// can act on — it retires the closed session and dials a new one.
type sessionStall struct {
	suspect atomic.Bool
	close   func() error
}

// observe records the outcome of one stream write. A successful write clears
// the pending strike; two timed-out writes without one in between close the
// session. A yamux connection write timeout is final on its own: yamux blocks
// the following write indefinitely.
func (s *sessionStall) observe(err error) { ... }
```

Rules for `observe`: `nil` → clear the flag; `errors.Is(err, yamux.ErrConnectionWriteTimeout)` → `close()` immediately; `errors.As(err, &net.Error)` with `Timeout()` → `close()` when `suspect.Swap(true)` was already set; anything else → ignore.

Then: add `stall *sessionStall` to `smuxSession` and `yamuxSession`; construct it in `newSMUXClientSession`, `newSMUXServerSession`, `newYamuxClientSession`, `newYamuxServerSession` after the backend session exists (`s.stall = &sessionStall{close: s.Close}`); pass it into every `streamConn`/`yamuxStreamConn` built by `GetConn`/`Accept`; and call `c.stall.observe(err)` from both `Write` implementations when `c.stall != nil`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd x && go test ./internal/util/mux/ -count=1 -timeout 120s`
Expected: PASS, whole package (the existing deadline test must still pass).

- [ ] **Step 5: Commit**

```bash
git -C x add internal/util/mux/mux.go internal/util/mux/mux_test.go
git -C x commit -m "fix(mux): close a session whose stream writes stop draining"
```

---

### Task 2: Bound a stream open by the caller's context

**Files:**
- Modify: `x/internal/util/mux/mux.go`
- Test: `x/internal/util/mux/mux_test.go`

**Interfaces:**
- Consumes: `streamConn`/`yamuxStreamConn` with `stall` from Task 1.
- Produces: `Config.OpenTimeout time.Duration`; `defaultOpenTimeout = 15 * time.Second`; `ErrOpenTimeout error`; `Session.GetConnContext(ctx context.Context) (net.Conn, error)`. Tasks 3 and 4 call `GetConnContext(ctx)` from `Handshake`.

- [ ] **Step 1: Write the failing tests**

```go
// A stalled open must return when the caller's context expires instead of
// waiting for smux's own 30s SYN timer.
func TestGetConnContextHonoursContextDeadline(t *testing.T)  // smux, ctx with 300ms deadline

// With no context deadline the configured open timeout is the backstop.
func TestGetConnContextUsesOpenTimeout(t *testing.T)         // smux, Config{OpenTimeout: 300ms}

// GetConn keeps its old behaviour: it opens on a healthy session.
func TestGetConnStillOpensOnHealthySession(t *testing.T)     // smux + yamux table
```

For the two timeout tests, create the client session over one end of `net.Pipe()` and keep the other end unread (no server session) so the SYN frame cannot be written; require the call to return within 2s with `context.DeadlineExceeded` (first) and `ErrOpenTimeout` (second) via `errors.Is`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd x && go test ./internal/util/mux/ -run 'TestGetConnContext|TestGetConnStill' -count=1 -timeout 60s`
Expected: FAIL — `GetConnContext` and `ErrOpenTimeout` do not exist.

- [ ] **Step 3: Implement in `mux.go`**

Add to `Config`: `OpenTimeout time.Duration` (comment: bounds a stream open when the caller's context has no deadline; 15s default, `mux.openTimeout` metadata).

Add the helpers:

```go
const defaultOpenTimeout = 15 * time.Second

// ErrOpenTimeout reports that a stream open exceeded its bound; the session
// should be treated as unusable by the caller.
var ErrOpenTimeout = errors.New("mux: open stream timeout")

// openBound is the shortest of the configured open timeout and ctx's
// remaining time.
func openBound(ctx context.Context, cfg *Config) time.Duration
```

Extend `Session` with `GetConnContext(ctx context.Context) (net.Conn, error)`; `GetConn()` becomes `return s.GetConnContext(context.Background())` in both backends.

`smuxSession.GetConnContext`: race `s.session.OpenStream()` in a goroutine against `time.NewTimer(openBound(...))` and `ctx.Done()`. On the open winning, return the usual `streamConn`. On the bound winning, start a second goroutine that reads the open's result and closes the stream if one arrives (so nothing leaks), then return `ctx.Err()` if the context expired, else `ErrOpenTimeout`. Mirror the same logic in `yamuxSession.GetConnContext` using `s.session.Open()`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd x && go test ./internal/util/mux/ -count=1 -timeout 120s`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C x add internal/util/mux/mux.go internal/util/mux/mux_test.go
git -C x commit -m "fix(mux): bound a stream open by the caller's context"
```

---

### Task 3: mtls — dial outside the lock, open outside the lock

**Files:**
- Modify: `x/dialer/mtls/dialer.go`, `x/dialer/mtls/metadata.go`
- Test: `x/dialer/mtls/dialer_test.go`

**Interfaces:**
- Consumes: `Session.GetConnContext`, `Config.OpenTimeout`, `ErrOpenTimeout` from Task 2.
- Produces: unexported helpers `sessionConn(addr string) net.Conn`, `sessionForHandshake(ctx, addr, conn) (*muxSession, error)`, `dropSession(addr string, session *muxSession)` on `*mtlsDialer`. Task 4 copies these into mtcp and mws.

- [ ] **Step 1: Write the failing tests**

```go
// A slow dial to one address must not hold up a dial to another: the TCP dial
// ran under sessionMutex, so one unreachable node stalled every service.
func TestDialDoesNotWaitForAnotherAddress(t *testing.T)

// After a session is dropped (as the stall guard does), the next handshake
// must build a new one and pass traffic.
func TestHandshakeRebuildsAfterSessionClosed(t *testing.T)
```

`TestDialDoesNotWaitForAnotherAddress`: a fake `dialer.Dialer` whose `Dial` blocks on a channel for `addrA` and returns a `net.Pipe()` end otherwise. Start `d.Dial(ctx, addrA, ...)` in a goroutine, then require `d.Dial(ctx, addrB, ...)` to return within 300ms with a non-nil conn; release the blocked dial at cleanup. `TestHandshakeRebuildsAfterSessionClosed`: use `echoServer`, `Dial`+`Handshake`+write/read once, then close the cached session directly (`d.(*mtlsDialer).sessions[addr].Close()`), then `Dial`+`Handshake` again and require the second round trip to succeed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd x && go test ./dialer/mtls/ -run 'TestDialDoesNotWait|TestHandshakeRebuilds' -count=1 -timeout 60s`
Expected: `TestDialDoesNotWaitForAnotherAddress` FAILS on the 300ms bound (mutex held by the blocked dial). `TestHandshakeRebuildsAfterSessionClosed` may already pass; keep it as the regression guard for this task.

- [ ] **Step 3: Rework `dialer.go` and `metadata.go`**

`Dial`: replace the body with a fast path (`if conn := d.sessionConn(addr); conn != nil { return conn, nil }`), then `options.Dialer.Dial` + keepalive + proxyproto **outside** the lock, then under the lock re-check (`if session, ok := d.sessions[addr]; ok && !session.IsClosed() { conn.Close(); return session.conn, nil }`) and register `&muxSession{conn: conn}`. `sessionConn` carries the existing closed-session cleanup verbatim (close the base conn only when `session.session != nil`, then `delete`).

`Handshake`: keep the placeholder-convergence block, but move it into `sessionForHandshake(ctx, opts.Addr, conn)` which runs under the lock and returns the session to use (building it via `initSession` when needed, and returning its error). Then call `session.GetConnContext(ctx)` **outside** the lock; on error call `dropSession(opts.Addr, session)` and return the error. `dropSession` closes and deletes only when the cached entry is still that exact session pointer.

`metadata.go`: add `OpenTimeout: mdutil.GetDuration(md, "mux.openTimeout")` to the `mux.Config` literal.

- [ ] **Step 4: Run the package tests**

Run: `cd x && go test ./dialer/mtls/ -count=1 -timeout 120s`
Expected: PASS, including the pre-existing `TestHandshakeAfterAnotherDial` in both orders.

- [ ] **Step 5: Commit**

```bash
git -C x add dialer/mtls/dialer.go dialer/mtls/metadata.go dialer/mtls/dialer_test.go
git -C x commit -m "fix(mtls): dial and open without holding sessionMutex"
```

---

### Task 4: Mirror the dialer changes into mtcp and mws

**Files:**
- Modify: `x/dialer/mtcp/dialer.go`, `x/dialer/mtcp/metadata.go`, `x/dialer/mws/dialer.go`, `x/dialer/mws/metadata.go`
- Test: `x/dialer/mtcp/dialer_test.go`, `x/dialer/mws/dialer_test.go`

**Interfaces:**
- Consumes: the three helpers produced by Task 3, adapted to each type (`*mtcpDialer`, `*mwsDialer`).
- Produces: nothing new; behaviour parity with mtls.

- [ ] **Step 1: Write the failing tests**

Add `TestDialDoesNotWaitForAnotherAddress` to both packages (same shape as Task 3). Add `TestHandshakeRebuildsAfterSessionClosed` to `mtcp` only if a listener harness already exists in that package; if it does not, skip it there and note the omission in the task's Implementation record — the mtls test already covers the rebuild path.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd x && go test ./dialer/mtcp/ ./dialer/mws/ -run TestDialDoesNotWait -count=1 -timeout 60s`
Expected: FAIL on the 300ms bound in both packages.

- [ ] **Step 3: Apply the Task 3 rework to both dialers**

`mtcp`: identical to mtls except the keepalive field is the same (`md.keepalive`) and there is no TLS in `initSession`. `mws`: identical except `initSession(ctx, host, conn, log, opts.Addr)` and the websocket reconnect goroutine must delete via the same pointer check (`if d.sessions[optAddr] == session { delete(...) }`) instead of an unconditional `delete`. Add `OpenTimeout: mdutil.GetDuration(md, "mux.openTimeout")` to both `mux.Config` literals.

- [ ] **Step 4: Run the package tests**

Run: `cd x && go test ./dialer/mtcp/ ./dialer/mws/ -count=1 -timeout 120s`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C x add dialer/mtcp dialer/mws
git -C x commit -m "fix(mtcp,mws): dial and open without holding sessionMutex"
```

---

### Task 5: Verification gate and records

**Files:**
- Modify: `x/docs/plans/2026-11-11-gost-925-mux-session-stall.md` (Implementation records)
- Modify: `x/docs/superpowers/specs/2026-11-11-gost-925-mux-session-stall-design.md` (evidence + what stays deferred)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Run the touched packages under the race detector**

Run: `cd x && CGO_ENABLED=1 go test -race -count=1 ./internal/util/mux/ ./dialer/mtls/ ./dialer/mtcp/ ./dialer/mws/`
Expected: PASS with no data race reports.

- [ ] **Step 2: Run the wider x packages that consume mux sessions**

Run: `cd x && go test -count=1 ./chain/ ./listener/mtls/ ./listener/mtcp/ ./listener/mws/ ./handler/relay/`
Expected: PASS.

- [ ] **Step 3: Build the binary from the gost module**

Run: `cd gost && go build ./cmd/gost`
Expected: exit 0, no output.

- [ ] **Step 4: Attempt the relay/tunnel e2e scenarios**

Run: `cd gost/tests/e2e && go test -count=1 -run 'Relay|MTLS|Mux|Tunnel' ./...`
Expected: PASS when Docker is available. If Docker is unavailable, record it as a limitation in the task record rather than skipping silently.

- [ ] **Step 5: Commit**

```bash
git -C x add docs/plans/2026-11-11-gost-925-mux-session-stall.md docs/superpowers/specs/2026-11-11-gost-925-mux-session-stall-design.md
git -C x commit -m "docs(plans): record gost#925 verification"
```

---

## Implementation Records

### Task 1

- Date/status: 2026-11-11 — complete
- Repo + commit: `x/` — this commit
- Files changed: `internal/util/mux/mux.go` (new `sessionStall`, `stall` field on both session types and both stream conns, `observe` on write), `internal/util/mux/mux_test.go` (`stallConn` + 4 new tests)
- Tests/commands and results: `go test ./internal/util/mux/ -count=1` PASS (5 tests, 1.2s); `go test -race ./internal/util/mux/` PASS; `go vet` clean; `gofmt` clean
- Review findings and fixes: two found while driving the tests. (1) Closing the session synchronously from `observe` deadlocks yamux — its `Close` waits for the send loop, which is exactly the goroutine blocked behind the write that reported the error; the close is now asynchronous. (2) The yamux session-level test took 10s because yamux's own `ConnectionWriteTimeout` fires before any stream deadline, so it was replaced with a direct `observe` unit test (plus a non-timeout negative test).
- Deferred items/limitations: the guard reacts to *write* timeouts only; a session that refuses to open streams is handled by Task 2. No e2e reproduction (needs an injectable transport fault).

### Task 2

- Date/status: 2026-11-11 — complete
- Repo + commit: `x/` — this commit
- Files changed: `internal/util/mux/mux.go` (`Config.OpenTimeout`, `defaultOpenTimeout`, `ErrOpenTimeout`, `Session.GetConnContext`, shared `openBound`/`openAwaited`, both backends), `internal/util/mux/mux_test.go` (3 new tests + `openBlockedSession` helper)
- Tests/commands and results: `go test ./internal/util/mux/ -count=1` PASS ×5; `-race` PASS ×3; `go vet` clean; `go build ./...` (x module) clean
- Review findings and fixes: the first implementation raced the configured timeout against `ctx.Done()` with one shared timer, so when the caller's deadline was the tighter bound the timer could fire first and report `ErrOpenTimeout` instead of `context.DeadlineExceeded` — flaky 4 runs in 6. `openBound` now reports which bound is tighter and, when it is the context, the code waits on `ctx.Done()` only; the abandon-and-close logic is shared in `openAwaited`. Five consecutive runs green after the fix.
- Deferred items/limitations: `Accept()` is deliberately unbounded; only dialers pass a context.

### Task 3

- Date/status: 2026-11-11 — complete
- Repo + commit: `x/` — this commit
- Files changed: `dialer/mtls/dialer.go` (`Dial` fast path + dial outside the lock, `sessionConn`, `sessionForHandshake`, `dropSession`, `GetConnContext` outside the lock), `dialer/mtls/conn.go` (`muxSession.GetConnContext`), `dialer/mtls/metadata.go` (`mux.openTimeout`), `dialer/mtls/dialer_test.go` (3 new tests)
- Tests/commands and results: `go test ./dialer/mtls/ -count=1` PASS (7 tests incl. ECH); `-race` PASS ×5; `go vet` clean; `go build ./...` clean
- Review findings and fixes: added `TestConcurrentDialHandshakeConvergesOnOneSession` because moving the dial out of the lock makes two concurrent `Dial`s register placeholders that can overwrite each other — the pre-existing convergence test only covered sequential cases. All 8 concurrent callers end on one established session, race-clean.
- Deferred items/limitations: `initSession` (TLS handshake) still runs under `sessionMutex` by design — it runs only on a cold/retired session and is bounded by ctx. The relay `tcpConn` half-close/promotion question and the resolved-vs-configured session key mismatch are untouched (see spec).

### Task 4

- Date/status:
- Repo + commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

### Task 5

- Date/status:
- Repo + commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:
