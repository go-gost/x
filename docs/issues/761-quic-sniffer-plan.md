# Plan: QUIC/HTTP3 SNI sniffer (issue go-gost/gost#761, Scope A)

## Context

Issue go-gost/gost#761 requests a QUIC/HTTP3 protocol sniffer, referencing the v2fly and Xray
implementations. GOST already sniffs **TCP** traffic (TLS/HTTP/SSH) via
`x/internal/util/sniffing/` to extract the SNI/Host for **bypass decisions and traffic recording**.
QUIC (HTTP/3) runs over **UDP** and is encrypted from the first packet, so it cannot flow through
the existing TCP `Sniff(*bufio.Reader)` path — there is currently **no UDP sniffing anywhere** in
the codebase (`grep udp` in `sniffing/`+`forwarder/` → nothing).

This plan adds **Scope A only**: sniff the QUIC Initial packet to extract the SNI (server_name) for
SNI-based bypass and recording, then forward datagrams transparently. **No MITM/termination** of
QUIC (that is Scope B — a far larger effort, intentionally excluded). The goal matches exactly what
Xray/v2fly do and what GOST's existing TLS sniffer achieves for TCP.

Outcome: a transparent UDP redirect (`redu`) service can apply bypass rules and record QUIC flows by
hostname, closing the HTTP/3 gap.

## Approach

The QUIC Initial parser is extracted into a **separate repo `quic-dissector/`** (parallel to
[`tls-dissector/`](../../../tls-dissector/)), following the same pattern: zero/minimal dependencies,
clean I/O boundary (bytes in → parsed info out), independently versioned, reusable by projects
outside GOST. The `x/` module consumes it as a standard Go dependency, just like it does
`tls-dissector`.

Three layers, lowest-risk-first.

### Phase 1 — `quic-dissector/` repo (new, parallel to `tls-dissector/`)

New repo `github.com/go-gost/quic-dissector` at workspace root `quic-dissector/`. Structure:

```
quic-dissector/
├── go.mod                  module github.com/go-gost/quic-dissector
│                           deps: tls-dissector + golang.org/x/crypto
├── dissector.go            SniffQUIC — public API
├── dissector_test.go       golden-packet tests + fuzz
├── internal/quic/
│   ├── varint.go           QUIC varint (~5 lines, avoids quic-go dep)
│   ├── hkdf.go             HKDF-Expand-Label per RFC 8446 §7.1 (~30 lines)
│   └── initial.go          Header protection removal + AEAD decrypt + CRYPTO reassembly
├── CLAUDE.md
├── README.md
├── LICENSE
└── .github/workflows/ci.yml
```

**Why separate repo** (same rationale as `tls-dissector`):
- Clean boundary: `[]byte` in, `*dissector.ClientHelloInfo` out, no I/O, no state
- Reusable: any Go project doing QUIC inspection needs this (Xray, v2fly, network monitors)
- Independently versionable: QUIC v2 (RFC 9369) has different salt + inverted type bits
- Nearly zero-dependency: only `x/crypto` (ubiquitous) + `tls-dissector` (same org, zero-dep)
- Precedent: `tls-dissector/` already established this pattern in the go-gost ecosystem

**Public API** (`dissector.go`):

```go
package quicdissector

import "github.com/go-gost/tls-dissector"

// ErrNotQUIC is returned when the datagram is not a parsable QUIC Initial packet.
var ErrNotQUIC = errors.New("not a QUIC Initial packet")

// SniffQUIC decrypts a QUIC Initial datagram and parses the embedded TLS ClientHello.
// Returns the ClientHello info (ServerName=SNI, SupportedProtos=ALPN),
// or ErrNotQUIC when the datagram cannot be parsed.
// Only the first datagram is parsed; cross-datagram ClientHello reassembly is out of scope.
func SniffQUIC(datagram []byte) (*dissector.ClientHelloInfo, error)
```

Returning `*dissector.ClientHelloInfo` directly (rather than separate `sni, alpn` strings)
gives callers access to all ClientHello fields (SupportedVersions, CipherSuites, etc.) at
zero extra cost. The `x/` handler extracts `.ServerName` and `.SupportedProtos[0]` for
bypass/recording — same fields the TCP TLS sniffer uses today.

Algorithm (port of Xray `common/protocol/quic/sniff.go`, confirmed against quic-go internals):

1. **Long-Header validation** — bit 7 set (`0x80`), fixed bit set (`0x40`); read 4-byte version;
   accept `0x00000001` (QUIC v1) and `0xff00001d` (draft-29). Reject short headers (1-RTT) — not
   sniffable.
2. **Packet type** — `(typeByte & 0x30) >> 4 == 0x0` = Initial; skip non-Initial long-header packets.
3. **DCID** (8–20 bytes) — the key material. Add an explicit `dcidLen` range guard Xray omits.
4. **Token** (varint-length, Initial-only) — skip.
5. **Packet length + header boundary** via QUIC varint (self-contained, ~5 lines — avoids pulling in
   `github.com/quic-go/quic-go/quicvarint`).
6. **Derive Initial keys** (HMAC-SHA256 HKDF, `golang.org/x/crypto/hkdf` + stdlib `crypto/aes`,
   `crypto/cipher`):
   - `initialSecret = HKDF-Extract(salt=QUIC_SALT, IKM=DCID)` — v1 salt
     `38762cf7f55934b34d179ae6a4c80cadccbb7f0a` (RFC 9001 §5.2).
   - `clientSecret = HKDF-Expand-Label(initialSecret, "client in", 32)`.
   - `hpKey  = HKDF-Expand-Label(clientSecret, "quic hp", 16)`,
     `key = …("quic key", 16)`, `iv = …("quic iv", 12)`.
   - `HKDF-Expand-Label` per RFC 8446 §7.1 (`"tls13 "+label`, 2B length + 1B label-len + 1B ctx-len).
     Self-contained implementation in `internal/quic/hkdf.go`.
7. **Remove header protection** — AES-ECB single-block of the 16-byte sample at offset 4 into the
   protected region; XOR low nibble of type byte (→ packet-number length) + up to 4 PN bytes.
8. **AEAD decrypt** — AES-128-GCM (`key`/`iv`), nonce = `iv` XOR truncated packet number, AAD = the
   full unmasked header. QUIC Initial protection is always AES-128-GCM regardless of negotiated cipher.
9. **CRYPTO frame reassembly** — within the decrypted payload, iterate frames (PADDING/PING/ACK/
   CRYPTO/CONNECTION_CLOSE); assemble `CRYPTO` (type `0x06`) data by offset into a buffer. Handle
   coalesced packets within the single datagram (Xray's outer loop).
10. **ClientHello SNI** — prepend a synthetic TLS record header (`0x16,0x03,0x03,<len>`) to the
    reassembled handshake bytes and call `dissector.ParseClientHello` (reuse — same parser the TCP
    TLS sniffer uses at `sniffer_tls.go:34`), returning the full `*ClientHelloInfo`.

Reuses: `dissector.ParseClientHello`. New deps: `golang.org/x/crypto` (hkdf). **No quic-go
dependency** — varint and HKDF-Expand-Label are self-contained.

**Limitation (documented):** parses only the ClientHello within the **first datagram** (handles
coalescing inside it). Cross-datagram ClientHello reassembly needs connection-state tracking and is
out of scope — note in a code comment. This covers the overwhelming majority of real traffic.

### Phase 2 — redirect/udp (`redu`) handler integration

`x/handler/redirect/udp/` is the clean mirror of `redirect/tcp` (both use `conn.LocalAddr()` as the
TPROXY destination and `xnet.Pipe`). The per-client `net.Conn` from `internal/net/udp/listener.go`
already buffers the first datagram by the time `Handle()` runs (the stateful listener Accepts on the
first datagram), so peeking will not block.

- **`metadata.go`** — add `sniffing bool` and `sniffingTimeout time.Duration`. Keys
  `mdutil.GetBool(md, "sniffing")`, `mdutil.GetDuration(md, "sniffing.timeout")` (mirror
  `redirect/tcp/metadata.go`). No `mitm.*` fields — Scope A does no MITM.
- **`handler.go` `Handle()`** — after `dstAddr := conn.LocalAddr()`, if `h.md.sniffing`:
  1. `conn.SetReadDeadline(now + sniffingTimeout)` (default from `sniffing.DefaultReadTimeout`).
  2. Read the first datagram into a buffer (one `Read` returns exactly the buffered datagram).
  3. `info, err := quicdissector.SniffQUIC(buf)`. Clear the read deadline.
  4. On success: set `ro.Host = net.JoinHostPort(info.ServerName, port)`, `ro.TLS = &xrecorder.TLSRecorderObject{ServerName: info.ServerName, Proto: info.SupportedProtos[0]}` (ALPN, may be empty). Apply SNI-based bypass via `h.options.Bypass.Contains(ctx, "udp", ro.Host, ...)` → `xbypass.ErrBypass` (mirrors `sniffer_tls.go:59`).
  5. Dial upstream to `dstAddr` (transparent — destination stays the original IP, SNI is for bypass/recording only), then forward the buffered first datagram + remaining via `xnet.Pipe`, prepending the buffered bytes with `xnet.NewReadWriteConn(io.MultiReader(bytes.NewReader(buf), conn), conn, conn)` (exact pattern from `redirect/tcp/handler.go:207`).
  6. On `quicdissector.ErrNotQUIC` / decode failure: fall through to the existing transparent-forward path, prepending the already-read datagram the same way so no data is lost.

`forward/local` UDP sniffing is a **secondary, optional** extension (its sniffing is currently gated
`network == "tcp"`). Defer unless requested — `redirect/udp` is the primary, cleanest target.

### Phase 3 — protocol constant + integration

- **`sniff.go`** — add `ProtoQUIC = "quic"` constant for recording consistency (the TCP `Sniff()`
  function itself is unchanged — it is TCP-only by design; QUIC has its own datagram entry point).
- **`handler/redirect/udp`** — build is the verification gate (no tests in this module per
  `x/CLAUDE.md`); a `play/` YAML for manual end-to-end verification (below).
- **`quic-dissector/` tests** — golden-packet table tests (`SniffQUIC` against captured QUIC Initial
  datagrams as hex literals with known SNI), plus negative cases (short header, non-Initial, truncated,
  bogus version). Fuzz test (`FuzzSniffQUIC`) for panic/DoS resistance. Mirror the fixture style in
  `tls-dissector/dissector_test.go`. Capture golden packets at implementation time via a one-off
  quic-go client or `openssl` to a test endpoint; commit as hex.

## Files to add / modify

### New repo: `quic-dissector/`

| File | Change |
|------|--------|
| `quic-dissector/go.mod` | **NEW** — module `github.com/go-gost/quic-dissector`, deps: `tls-dissector` + `golang.org/x/crypto` |
| `quic-dissector/dissector.go` | **NEW** — `SniffQUIC` public API |
| `quic-dissector/dissector_test.go` | **NEW** — golden-packet unit tests + fuzz |
| `quic-dissector/internal/quic/varint.go` | **NEW** — QUIC varint (~5 lines) |
| `quic-dissector/internal/quic/hkdf.go` | **NEW** — HKDF-Expand-Label per RFC 8446 §7.1 (~30 lines) |
| `quic-dissector/internal/quic/initial.go` | **NEW** — header protection removal + AEAD decrypt + CRYPTO reassembly |
| `quic-dissector/CLAUDE.md` | **NEW** — build/test instructions |
| `quic-dissector/.github/workflows/ci.yml` | **NEW** — CI (vet + test + fuzz loop, mirror tls-dissector) |

### Existing repo: `x/`

| File | Change |
|------|--------|
| `x/go.mod` | add `github.com/go-gost/quic-dissector v0.1.0` |
| `x/internal/util/sniffing/sniff.go` | add `ProtoQUIC` constant |
| `x/handler/redirect/udp/metadata.go` | add `sniffing`, `sniffingTimeout` fields + parse keys |
| `x/handler/redirect/udp/handler.go` | sniff-first-datagram branch (bypass + recording + prepend) |
| `play/quic-sniff.yaml` (or similar) | manual e2e config (TPROXY UDP → QUIC upstream w/ bypass rule) |

Reused, existing code (do not duplicate): `dissector.ParseClientHello` (`tls-dissector/dissector.go`),
`sniffing.DefaultReadTimeout`, `xnet.NewReadWriteConn`/`Pipe`,
`xrecorder.TLSRecorderObject`, `xbypass.ErrBypass`, `mdutil.GetBool/GetDuration`.

## Verification

1. **`quic-dissector/` build + test** (own CI, mirror `tls-dissector`):
   `cd quic-dissector && go build ./... && go vet ./... && go test -v -cover ./...`
   Golden packets must round-trip the expected SNI; negative cases must return `ErrNotQUIC` without
   false positives. Fuzz test runs 30s in CI.
2. **`x/` build + vet** (per `x/CLAUDE.md`, the module's verification path):
   `cd x && go build ./... && go vet ./...`
   Confirms the `quic-dissector` import compiles and the handler integration is correct.
3. **Manual e2e** (transparent UDP redirect): run the `play/` config with `sniffing: true` and a
   bypass rule on a known QUIC hostname; `curl --http3 https://<host>` through the redirect and
   confirm (a) the bypass rule fires for the SNI, (b) non-bypassed QUIC still reaches the upstream,
   (c) recorder logs show `ro.TLS.ServerName` populated.

## Notes / scope boundaries

- **Scope A only** — sniff SNI + transparent forward. No QUIC MITM/termination (Scope B).
- **QUIC v1 + draft-29** initially (matches proven Xray code). QUIC **v2** (`0x6b3343cf`, different
  salt + inverted type bits, RFC 9369) is a small follow-up enhancement — noted in a code comment.
- **Single-datagram** ClientHello parsing; cross-datagram reassembly out of scope (documented).
- **Separate repo** (`quic-dissector/`) — follows the `tls-dissector/` pattern. The parser is
  self-contained, independently versioned, and reusable by projects outside GOST. The `x/` module
  consumes it as a standard Go dependency.
- **No quic-go dependency** — varint and HKDF-Expand-Label are self-contained implementations
  (~35 lines total). Only external dep is `golang.org/x/crypto` (hkdf).
- Comments in **English only** (project convention). Doc comments on all exported symbols.
