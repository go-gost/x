# Design: Tunnel Mux Negotiation via Relay Protocol Extension

**Date:** 2026-07-13
**Status:** Design proposal (follow-up to `2026-07-13-mux-pluggable-yamux.md`)
**Scope:** Server-side multi-mux support for the tunnel handler, with the client
selecting the mux method per connection — negotiated through a new relay-protocol
feature, SOCKS5-style. Backward compatible; no change to the existing wire protocol.

## Problem

Today the tunnel handler multiplexes streams with a single hard-wired backend
(`github.com/xtaci/smux`), chosen statically per component via `mux.type`
metadata. We want the tunnel server to support several mux methods at once
(smux + yamux) and let each client pick one, **without changing the existing
wire protocol and without breaking old peers**.

## Key finding: the negotiation window already exists

In the tunnel path the relay `CmdBind` handshake runs on the **raw `net.Conn`
before** the mux session is created on that same connection:

```
raw conn:  relay Request (CmdBind)  →  relay Response  →  mux.ClientSession / mux.ServerSession  →  streams
```

Confirmed at:
- Server (`handler/tunnel/`): `req.ReadFrom(conn)` → `handleBind` writes `resp` → `mux.ClientSession(conn)`.
- Client (`connector/tunnel/bind.go`): `req.WriteTo(conn)` → `resp.ReadFrom(conn)` → `mux.ServerSession(conn)`.

So a mux-method choice carried in the relay exchange is available in time to
drive the `muxCfg` passed to `mux.ClientSession`/`ServerSession`.

## Design

### 1. New relay feature type

Add `FeatureMux` (e.g. `0x05`) to `relay/feature.go`. Payload = list of
supported mux methods, encoded as method IDs (sketch: `1=smux`, `2=smux2`,
`3=yamux`). Mirror the existing `AddrFeature`/`TunnelFeature` pattern:
`TYPE(1) + LEN(2) + DATA`.

- **Client** (`connector/tunnel/bind.go`, `connector/relay/bind.go`): append
  `FeatureMux` (supported methods) to `Request.Features`.
- **Server** (`handler/tunnel/handler.go` → `handleBind`): read it, pick a
  mutually supported method (or its configured default), echo the **chosen**
  method in `Response.Features`.
- Both ends build `muxCfg` for `mux.ClientSession`/`ServerSession` from the
  agreed method instead of static metadata alone.

The relay protocol has no built-in "offer-N / pick-one" opcode — it's symmetric
feature lists — but a feature whose payload is a method list, with the server
echoing the chosen one, reuses the existing echo shape. No protocol change.

### 2. Mux package abstraction (shared with the implementation plan)

`x/internal/util/mux` gains a `mux.Session` interface with an smux backend and a
yamux backend; the negotiated feature selects the implementation + version. This
is the same refactor as `2026-07-13-mux-pluggable-yamux.md`.

## Backward compatibility

- **Wire format unchanged.** We only add a feature type to the existing
  `Features []Feature` list. Old peers are unaffected.
- **`OpaqueFeature` guarantees graceful fallback.** A peer with no `case FeatureMux`
  simply drops the feature (never errors). So:
  - Old smux-only client → new server: no `FeatureMux` sent, server falls back to
    its configured/default mux = byte-identical to today.
  - New client offering `yamux` → old server: server ignores the feature, client
    sees no chosen method, falls back to its default (`smux`). No break.

This satisfies both constraints: 不改变当前协议 and 向后兼容.

## Constraints

1. **Timing is hard, not soft.** `smux.Client/Server` send/parse a version frame
   immediately at session creation; mismatched impl/version fails the handshake.
   Because `CmdBind` precedes it, the agreed choice is in time — *provided both
   ends build `muxCfg` from the agreed feature, not static metadata alone.*
2. **Coverage = relay-based mux family only.** The negotiation window exists for
   tunnel handler, tunnel connector, relay handler, relay connector (all do
   `CmdBind` on the raw conn before mux). The **raw** mux tunnels
   (`listener/mtcp|mws|mtls` and their dialers) call `mux.ServerSession`/
   `ClientSession` directly with no relay handshake first, so they keep using the
   static `mux.type` from the implementation plan.
3. **`relay/` is a separate zero-dependency module.** `FeatureMux` lives there,
   consumed by `x/`. Adding a feature type is backward-compatible but is a
   protocol-library change — deliberate, not casual.

## Relationship to the implementation plan

This negotiation design **extends** `2026-07-13-mux-pluggable-yamux.md`; it does
not replace it. The mux package still gets the interface + yamux backend, and the
static `mux.type` remains the default/fallback for raw-mux paths. The relay
`FeatureMux` adds server-side multi-mux support + per-connection client selection
for the tunnel/relay paths.

## Open questions (for later, when implementing)

- Exact `FeatureMux` payload encoding (method-ID list vs. string tags).
- How the server's supported-methods set is configured (metadata keys like
  `mux.supported` / `mux.types`).
- Whether `connector/socks/v5` muxbind (SOCKS5, not relay) should get an
  analogous SOCKS5-method negotiation, or stay static.
