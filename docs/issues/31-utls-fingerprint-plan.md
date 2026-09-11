# Plan: Add uTLS Fingerprint Dialer (`utls`)

## Context

**Issue**: [go-gost/gost#31](https://github.com/go-gost/gost/issues/31) — Feature request to add TLS ClientHello fingerprint simulation using the [uTLS](https://github.com/refraction-networking/utls) library. GOST currently uses Go's `crypto/tls` which produces a distinctive Go TLS fingerprint that's easily blocked. Users want to mimic Chrome/Firefox/Safari/etc. fingerprints.

**Approach**: New `"utls"` dialer type (standalone, not modifying the existing `"tls"` dialer). The fingerprint is dialer-only metadata — not on the shared `TLSConfig` struct. This keeps the standard TLS dialer untouched and avoids pulling in the uTLS dependency for all users.

## Files to Create

### 1. `x/dialer/utls/fingerprint.go` — String→ClientHelloID map

Maps user-facing fingerprint names to `utls.ClientHelloID` presets. Supported names: `chrome`, `firefox`, `ios`, `safari`, `edge`, `randomized`, `randomized-alpn`, `randomized-noalpn`, `golang`, `custom`. Empty string and `"golang"` both mean "fall through to standard crypto/tls" (return `ok=false`). Unknown names get a warning log and also fall through.

### 2. `x/dialer/utls/metadata.go` — Metadata parsing

Mirrors `dialer/tls/metadata.go` exactly, adding a `fingerprint string` field. Parsed keys:
- `handshakeTimeout` (duration)
- `keepalive`, `keepalive.idle`, `keepalive.interval`, `keepalive.count` (TCP keepalive)
- `fingerprint` (string) — **new**

### 3. `x/dialer/utls/dialer.go` — Core dialer

Mirrors `dialer/tls/dialer.go`. Registered as `"utls"`. The `Dial()` method is identical to the TLS dialer. The `Handshake()` method diverges: looks up the fingerprint; if `ok`, uses `utls.UClient(conn, tlsConfig, clientHelloID)`; otherwise falls through to `crypto/tls.Client()`.

## Files to Modify

### 4. `x/go.mod` — Add uTLS dependency

Add `github.com/refraction-networking/utls v1.8.2` to the require block, then run `go mod tidy` from `x/`.

### 5. `gost/cmd/gost/register.go` — Blank import

Add `_ "github.com/go-gost/x/dialer/utls"` in the "Register dialers" section, alphabetically between the `unix` and `ws` imports.

## No Changes Needed

- **Config parsing** — `node/parse.go` already passes `dialCfg.Metadata` to `d.Init()`; no changes required to any parsing code.
- **`config/config.go`** — `DialerConfig.Metadata` already supports arbitrary keys; `fingerprint` flows through naturally.
- **Metadata key constants** — No new constant in `config/parsing/parse.go`; local `const` in `parseMetadata()` follows existing dialer convention.

## Usage Example

```yaml
services:
  - name: service-0
    addr: :8080
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target-0
          addr: example.com:443
          dialer:
            type: utls
            metadata:
              fingerprint: chrome
```

## Verification

```bash
# 1. Tidy dependencies
cd x && go mod tidy

# 2. Build + vet the x module
cd x && go build ./... && go vet ./...

# 3. Build + vet the gost binary (verifies blank import)
cd gost && go build ./cmd/gost/... && go vet ./...
```

No unit tests needed — the existing codebase has no tests in `x/dialer/`.
