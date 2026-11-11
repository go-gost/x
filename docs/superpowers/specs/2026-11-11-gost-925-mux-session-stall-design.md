# Mux session stall: no recovery after the send path stops draining

**Issue:** go-gost/gost#925 — "GOST relay+mtls client remains alive but stops forwarding and does not recover"
**Date:** 2026-11-11
**Status:** implemented

## Symptom

A long-running client with `-F relay+mtls://…` keeps running but every new connection
through the chain times out; DNS listeners report timeouts; a fresh client process using
the same server works. The client log holds 18,591 entries, all errors, all from the two
DNS services.

## Evidence from the attached logs

| observation | source |
|---|---|
| `service-4` (TCP DNS through the chain) logs the bare error `timeout` 9,288 times | `gost-2001-20261107.log` |
| `service-5` (UDP DNS front → `tcp://127.0.0.1:2052`) logs `read tcp 127.0.0.1:x->127.0.0.1:2052: i/o timeout` 9,292 times, always within the same millisecond as a `timeout` | same |
| one base TCP connection carried five concurrent sessions (`[2001:db8:1::10]:43988 → [2001:db8:2::20]:10000`) | same, 07:55:24 |
| no `route(retry=N) dial …` line after 07:53:50 — the chain never failed a dial during the stall | same |
| the server logged nothing for this client between 20:30 and 22:26, then exactly one `accept stream: EOF` at 22:26:24.882 | `server-side.log` |
| the client logged `io: read/write on closed pipe` at 22:26:24.857 | client log |

Bare `timeout` is not produced anywhere in gost or its direct dependencies except
`xtaci/smux`'s `ErrTimeout` (`timeoutError.Error() == "timeout"`). It is returned from
`stream.Write` when the frame cannot be handed to the socket within the stream's write
deadline. The DNS exchanger sets a 5 s deadline, which matches the paired
`i/o timeout` from the parent service.

So the client was not failing to *connect*: `route.Dial` returned successfully (the relay
connector buffers its request in `tcpConn.wbuf` and touches the network only on the
first caller `Write`), and the first write to the mux stream stalled.

## Root cause

`mtls` owns one `muxSession` per node address, shared by every service on the chain
(`x/dialer/mtls/dialer.go`). Two independent liveness checks miss a session whose
*send* direction is dead while its *receive* direction is alive:

- smux's keepalive closes the session only after `KeepAliveTimeout` with no **received**
  frame (`sessionIsActive` is set in `recvLoop`). A peer that keeps sending NOPs while it
  stops reading its socket keeps the session "active" forever.
- TCP keepalive is answered by the peer's kernel, not its application, so it also cannot
  see a receiver that no longer drains its socket.

The only code path that retires a session is an error from `session.GetConn()`
(`Handshake` → `Close()` + `delete`). A stalled **write** surfaces in the caller — the
DNS exchanger, the relay pipe, an HTTP handler — long after `Dial`/`Handshake` returned,
so nothing rotates the session. Every later connection multiplexes onto the same dead
tunnel, and the process never recovers. A new process dials a new tunnel, which is why the
reporter's second client worked.

Two secondary defects made the stall worse:

- `Handshake` held `sessionMutex` across `GetConn()`, whose open is bounded only by
  smux's hard-coded `openCloseTimeout` (30 s) and ignores `ctx` — one bad session
  serialised every chain dial in the process for 30 s each.
- `Dial` held the same mutex across the TCP dial, so an unreachable node stalled dials
  for *other* addresses.

## Decision

Close the session; never try to repair it. Recovery comes from the owner rebuilding it.

1. **Write-stall guard** (`sessionStall`, `x/internal/util/mux`): a timed-out stream
   write is the only signal a stalled send path gives, but on its own it is not proof —
   a slow peer produces the same error through back-pressure, and gost itself sets a 10 s
   write deadline on the surviving half of a piped transfer
   (`internal/net/pipe.go`). So the session is closed on **two strikes with no completed
   write for a whole window** (`Config.StallWindow` / `mux.stallWindow`, 10 s default).
   A yamux `ErrConnectionWriteTimeout` is final on its own (the next write blocks
   indefinitely). Every stream conn, on both the dialer and the listener side, observes
   its writes.
   *Accepted cost:* a false positive drops every stream multiplexed on that session; the
   owner rebuilds on the next dial. The window makes that unlikely, and the guard never
   fires on a session that is still moving bytes.
2. **Bounded open**: `Session.GetConnContext(ctx)` races the backend open against the
   caller's deadline and a `mux.openTimeout` backstop (default 15 s, matching
   `chain.Router`'s default), returning `ctx.Err()` or `ErrOpenTimeout`. `GetConn()`
   delegates with `context.Background()`; `Accept()` is never bounded.
3. **Narrower locking** in `mtls`/`mtcp`/`mws`: the TCP dial and the stream open run
   outside `sessionMutex`, and `initSession` runs under a **per-address** builder, so a
   node that accepts TCP and then stalls its TLS/WS handshake no longer holds up dials to
   other addresses (or the reuse fast path). Only map access is global.
   `dropSession` deletes only when the cached entry is still the exact session pointer,
   and closes outside the mutex because a backend's `Close` may wait for its own send
   loop. The `handshakeTimeout` deadline is applied only to a conn the caller owns: on
   the reused session conn it would bound its reads and could kill a live session.

## Scope and caveats

- The guard and the open bound live in `x/internal/util/mux`, so they apply to **every**
  session built there — including `connector/{relay,socks/v5,tunnel}`,
  `handler/{relay,tunnel}` bind and entrypoint sessions. Their owners do not rebuild on
  failure (`handler/relay/entrypoint.go` logs and returns), so for those paths a stalled
  session now fails fast instead of hanging: better, but not self-healing. Only the three
  mux dialers were changed to rebuild.
- `mux.openTimeout` and `mux.stallWindow` are wired in `dialer/{mtls,mtcp,mws}` only. The
  other `mux.*` consumers still get the defaults.
- `IsClosed()` reports true for a session still waiting for its handshake, so "closed" as
  used by the dialers means "not usable yet"; the distinction is preserved deliberately
  to keep this change behaviour-preserving.

## Tests

Unit tests with `net.Pipe()` as the stallable transport:

- `TestSessionClosesAfterRepeatedWriteTimeouts` — two timed-out writes close a silent
  session.
- `TestSessionSurvivesSingleWriteTimeout` — a successful write clears the strike.
- `TestSessionStallRequiresSilence` — strikes alone do not close a busy session; silence
  does.
- `TestYamuxConnectionWriteTimeoutClosesSession`, `TestSessionStallIgnoresNonTimeoutErrors`.
- `TestGetConnContextHonoursContextDeadline`, `TestGetConnContextUsesOpenTimeout`,
  `TestGetConnStillOpensOnHealthySession`.
- `TestDialDoesNotWaitForAnotherAddress` (mtls, mtcp, mws) — a blocked dial to one address
  does not delay a dial to another.
- `TestHandshakeStallDoesNotBlockOtherAddresses` (mtls, mtcp, mws) — a stalled TLS/WS
  handshake does not delay a healthy address (1.98 s before the per-address builder,
  20 ms after).
- `TestHandshakeRebuildsAfterSessionClosed` (mtls, mtcp, mws) — a dropped session is
  rebuilt on the next handshake and carries traffic.
- `TestStalledWritesRetireTheSession` (mtls, mtcp, mws) — the composition the issue is
  named after: a real session, gated writes, two timed-out writes, the session is
  retired, and the next dial works.
- `TestConcurrentDialHandshakeConvergesOnOneSession` (mtls, mtcp, mws) — eight concurrent
  callers still end on one session with the locking narrowed.

## Still open (not in this change)

- **No end-to-end reproduction.** Stalling a real peer's read path needs an injected
  transport fault, which the current e2e harness does not have; the unit tests pin the
  semantics at the mux boundary instead.
- **Yamux wiring is tested only indirectly.** Driving a real yamux session into
  `ErrConnectionWriteTimeout` takes its own 10 s connection timeout, so the guard's yamux
  branch is asserted on `observe` rather than through a stream; the smux path is covered
  end to end.
- **Session key mismatch with a configured node resolver**: `Dial` keys the session map by
  the resolved candidate address while `Handshake` keys it by `Transport.options.Addr`
  (the configured hostname). With `resolver=` set on the chain this means one throwaway
  TCP connect per chain dial. Needs its own issue/fix.
- **The trigger is still unknown.** The logs prove where the stall was, not what started
  it. The diagnostics requested from the reporter (goroutine dump, `ss -tinp` on both
  ends, debug-level logs, identical comparison client including `so_mark`) remain the way
  to settle that.
