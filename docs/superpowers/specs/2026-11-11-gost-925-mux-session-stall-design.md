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

1. **Write-stall guard** (`sessionStall`, `x/internal/util/mux`): a stream write that
   times out means the frame never reached the socket. Two of them with no successful
   write in between close the session. A yamux `ErrConnectionWriteTimeout` is final on
   its own (the next write blocks indefinitely). Every stream conn, on both the dialer
   and the listener side, observes its writes.
2. **Bounded open**: `Session.GetConnContext(ctx)` races the backend open against the
   caller's deadline and a `mux.openTimeout` backstop (default 15 s, matching
   `chain.Router`'s default), returning `ctx.Err()` or `ErrOpenTimeout`. `GetConn()`
   delegates with `context.Background()`; `Accept()` is never bounded.
3. **Narrower locking** in `mtls`/`mtcp`/`mws`: the TCP dial and the stream open both run
   outside `sessionMutex`; only map access and `initSession` convergence stay inside.
   `dropSession` deletes only when the cached entry is still the exact session pointer.

`initSession` (TLS handshake) stays under the mutex deliberately: it runs only when no
session exists, it is bounded by `ctx`, and splitting it would weaken the
one-session-per-address convergence fixed in `6911ecd`.

## Tests

Unit tests with `net.Pipe()` as the stallable transport:

- `TestSessionClosesAfterRepeatedWriteTimeouts` — two timed-out writes close the session.
- `TestSessionSurvivesSingleWriteTimeout` — a successful write clears the strike.
- `TestYamuxSessionClosesOnConnectionWriteTimeout`.
- `TestGetConnContextHonoursContextDeadline`, `TestGetConnContextUsesOpenTimeout`,
  `TestGetConnStillOpensOnHealthySession`.
- `TestDialDoesNotWaitForAnotherAddress` (mtls, mtcp, mws) — a blocked dial to one address
  does not delay a dial to another.
- `TestHandshakeRebuildsAfterSessionClosed` (mtls) — a dropped session is rebuilt on the
  next handshake and carries traffic.

## Still open (not in this change)

- **No end-to-end reproduction.** Stalling a real peer's read path needs an injected
  transport fault, which the current e2e harness does not have; the unit tests pin the
  semantics at the mux boundary instead.
- **Session key mismatch with a configured node resolver**: `Dial` keys the session map by
  the resolved candidate address while `Handshake` keys it by `Transport.options.Addr`
  (the configured hostname). With `resolver=` set on the chain this means one throwaway
  TCP connect per chain dial. Needs its own issue/fix.
- **The trigger is still unknown.** The logs prove where the stall was, not what started
  it. The diagnostics requested from the reporter (goroutine dump, `ss -tinp` on both
  ends, debug-level logs, identical comparison client including `so_mark`) remain the way
  to settle that.
