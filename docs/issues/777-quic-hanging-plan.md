# Plan: go-gost/gost#777 - relay+quic hanging under high load

## Issue Summary

- **Reporter**: @qianhd
- **Config**: `gost -L socks5://:10086 -F relay+quic://IP:PORT?keepalive=true&ttl=21s&auth=XXXX`
- **Version**: 3.2.4 (docker)
- **Symptom**: Under frequent requests, connections are accepted (handler logs visible) but no forwarding occurs (no forwarding logs). Restarting the container immediately recovers.
- **Maintainer comment**: "May related to connection multiplexing or reuse" (@fernvenue)

## Version Context - prior analysis is partly stale

The earlier analysis (777-quic-hanging-analysis.md) was written against v3.2.4 and named three root causes (global mutex held during OpenStreamSync, no timeout on OpenStreamSync, no IsClosed check). All three are already fixed on current main:

- 5484717 (2026-06-20): added quicSession.IsClosed() and the reuse-time liveness guard in Dial().
- 9fab332 (2026-06-21): added the 30s timeout on OpenStreamSync, and released sessionMutex before GetConn() so a dead session can no longer stall all Dial() calls.

This plan covers only the remaining real problems (P1-P3) plus doc correction. The sibling icmp dialer shares the quicSession type and the same structure, so every quic change is mirrored to icmp.

## Root Cause Analysis (current main)

### P1 (HIGH): request ctx not propagated to GetConn / OpenStreamSync

- Router applies a default 15s timeout (x/chain/router.go:36 sets Timeout = 15s) and wraps the context with context.WithTimeout(ctx, 15s) (x/chain/router.go:108). This ctx flows into quicDialer.Dial(ctx, ...) via route.Dial -> transport.Dial -> dialer.go:50.
- But dialer.go calls session.GetConn() without ctx, and conn.go builds its own context.WithTimeout(context.Background(), 30s). The request ctx (deadline + cancellation) is dropped.
- Consequence: OpenStreamSync neither honors the 15s request deadline nor cancels when the inbound request is cancelled. A stuck QUIC session still blocks each new connection on OpenStreamSync for up to 30s (single-connection hang, no longer global).

### P2 (MEDIUM): keepalive asymmetric between dialer and listener

- Dialer (x/dialer/quic/metadata.go:35): `md == nil || !md.IsExists(keepAlive) || GetBool(keepAlive)` -> keepalive ON by default (period 10s).
- Listener (x/listener/quic/metadata.go:47): `if GetBool(keepAlive)` -> only ON when explicitly set.

If the user only configures keepalive=true on the client (-F), the server-side QUIC listener sends no PING. Across a NAT the server's return-path mapping can expire while the client still thinks the connection is alive - matching the reported symptom.

### P3 (LOW): no explicit MaxIdleTimeout default on either side

Both dialer and listener parse maxIdleTimeout into quic.Config.MaxIdleTimeout with a default of 0 -> quic-go's own default (~30s), with no explicit floor. A symmetric, reasonable explicit default (90s) lets quic-go itself detect dead sessions sooner, complementing P2.

## Fix Plan

### Fix B (P1, HIGH): propagate request ctx into GetConn

- x/dialer/quic/conn.go: change `GetConn()` to `GetConn(ctx context.Context)` and use
  `ctx, cancel := context.WithTimeout(ctx, 30*time.Second)` (keep the 30s cap, but the
  parent ctx now carries the 15s request deadline and cancellation).
- x/dialer/quic/dialer.go:101: call `session.GetConn(ctx)`.
- Mirror to x/dialer/icmp/conn.go and x/dialer/icmp/dialer.go:120 (identical structure).

### Fix C (P2, MEDIUM): symmetric listener keepalive default

- x/listener/quic/metadata.go:47: change `if mdutil.GetBool(md, keepAlive)` to
  `if md == nil || !md.IsExists(keepAlive) || mdutil.GetBool(md, keepAlive)` so the
  server side sends keepalive by default (period 10s). No new struct field is needed -
  keepAlivePeriod is already parsed.

### Fix D (P3, LOW): explicit MaxIdleTimeout default

- x/dialer/quic/metadata.go, x/dialer/icmp/metadata.go, x/listener/quic/metadata.go:
  after parsing maxIdleTimeout, if `<= 0` set to `90 * time.Second`. Users can still
  override via `maxIdleTimeout=`.

### Fix A (docs): correct the two issue docs

- 777-quic-hanging-analysis.md and this file: mark PRIMARY/SECONDARY/TERTIARY as already
  fixed on main (commits 5484717, 9fab332); rename the remaining items to P1-P3.

## Sibling pattern note

kcp / masque / mtls / mtcp / mws / ssh hold the lock for the whole Dial (their stream-open
is non-blocking). quic / icmp are the only two using the narrow-lock variant (unlock before
GetConn), and their code is byte-for-byte identical - so every quic change is mirrored to
icmp. There is no shared session-cache abstraction to reuse; extraction is out of scope.

## Verification

```bash
cd x && go build ./... && go vet ./...
cd gost && go build ./cmd/gost/...
```

E2e (issue-like config):

```bash
# server: $GOST_BIN -L "relay+quic://:8443?keepalive=true"
# client: $GOST_BIN -L socks5://:10086 -F "relay+quic://SERVER:8443?keepalive=true&ttl=21s"
```

- Fix B: under high concurrency with a cancelled request, confirm OpenStreamSync returns on
  ctx cancellation instead of blocking up to 30s.
- Fix C: server WITHOUT explicit keepalive=true should still have quic.Config.KeepAlivePeriod > 0.
- Fix D: without maxIdleTimeout set, confirm quic.Config.MaxIdleTimeout == 90s on both sides.

## Out of scope (optional follow-ups)

- Move initSession (quic.DialEarly handshake) out of sessionMutex (double-check / per-key lock).
- Background session health-check goroutine (IsClosed reuse check already covers dead sessions).
- Extract a shared session-cache abstraction across kcp/quic/icmp/ssh/masque (new abstraction).
