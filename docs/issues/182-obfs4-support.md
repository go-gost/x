# Plan: obfs4 Pluggable Transport Support (go-gost/gost#182)

## Context

Issue [#182](https://github.com/go-gost/gost/issues/182) requests obfs4 support. GOST v3 currently has `ohttp` (HTTP WebSocket upgrade) and `otls` (fake TLS handshake) obfuscation, but not obfs4 — the "look-like-nothing" pluggable transport used by Tor bridges. The maintainer confirmed in the issue comments that obfs4 was not yet implemented. The `feature` label indicates this is desired functionality.

## Approach: Use external library

Use **`github.com/refraction-networking/obfs4`** (BSD-licensed) — the same organization that provides `refraction-networking/utls` already depended on by GOST. This library implements the full obfs4 protocol (ntor handshake, Elligator 2 key obfuscation, NaCl secretbox framing, SipHash length masking, replay filtering).

### Why this library vs implementing from scratch

| Factor | Library | From scratch |
|--------|---------|-------------|
| Cryptographic safety | Battle-tested (used by Tor/Refraction Networking) | Risk of subtle bugs in Elligator 2, ntor, constant-time ops |
| Code volume | ~200 lines of GOST wrappers | ~1500+ lines of complex crypto code |
| Maintenance | Upstream maintains protocol compliance | GOST maintainers own all crypto code |
| Dependency footprint | Adds ~3 transitive deps | None new |
| Integration fit | `ServerFactory.WrapConn()` is a perfect match for Accept(); `ClientFactory.Dial()` needs a thin bridge in Handshake() | Full control |

The library approach matches how GOST already uses `refraction-networking/utls` for TLS fingerprinting.

## Files to Create

### 1. `x/listener/obfs/obfs4/listener.go`
- Registers `"obfs4"` in `ListenerRegistry`
- `obfsListener` struct following the same pattern as `listener/obfs/tls/listener.go` and `listener/obfs/http/listener.go`
- `NewListener()` factory, `Init(metadata)`, `Accept()` methods
- In `Accept()`: wrap accepted conn with limiter, then call `serverFactory.WrapConn(conn)` to perform server-side obfs4 handshake

### 2. `x/listener/obfs/obfs4/conn.go`
- Thin: the library's `WrapConn` already returns a `net.Conn` that handles framing transparently
- May not even need a custom conn type — `WrapConn` returns a fully functional `net.Conn`

### 3. `x/listener/obfs/obfs4/metadata.go`
- Parse server-side config: `nodeId` (hex), `privateKey` (base64), `iatMode` (int, default 0)
- Construct `pt.Args` from metadata for `ServerFactory()`

### 4. `x/dialer/obfs/obfs4/dialer.go`
- Registers `"obfs4"` in `DialerRegistry`
- `obfs4Dialer` struct following the same pattern as `dialer/obfs/tls/dialer.go`
- `NewDialer()`, `Init(metadata)`, `Dial()`, `Handshake()` methods
- `Dial()`: delegates to options.Dialer (standard raw TCP connection)
- `Handshake()`: uses `ClientFactory.Dial()` with a passthrough `DialFunc` that returns the already-established conn — the library then performs the obfs4 client handshake on it

### 5. `x/dialer/obfs/obfs4/metadata.go`
- Parse client-side config: `cert` (base64, required), `iatMode` (int)
- Store state dir path for client factory

### 6. Update `gost/cmd/gost/register.go`
- Add blank imports:
  ```go
  _ "github.com/go-gost/x/listener/obfs/obfs4"
  _ "github.com/go-gost/x/dialer/obfs/obfs4"
  ```

## Key Design Decisions

### Server-side: Use `ServerFactory.WrapConn()`
The library's `base.ServerFactory` interface has `WrapConn(conn net.Conn) (net.Conn, error)` which is an exact match for GOST's `Accept()` pattern — it takes a raw TCP connection, performs the obfs4 server handshake, and returns a wrapped connection. No custom conn type needed.

### Client-side: Bridge Dial/Handshake with passthrough DialFunc
The library's `ClientFactory.Dial(network, address, DialFunc, args)` both connects AND handshakes. GOST separates these. Solution:

```go
func (d *obfs4Dialer) Handshake(ctx context.Context, conn net.Conn, ...) (net.Conn, error) {
    cf, _ := d.transport.ClientFactory(d.md.stateDir)
    args, _ := cf.ParseArgs(d.md.ptArgs)
    return cf.Dial("tcp", "", func(network, address string) (net.Conn, error) {
        return conn, nil // passthrough — conn already established
    }, args)
}
```

### Config interface
Users configure obfs4 via YAML/JSON metadata, mirroring Tor's bridge line format:

**Server** (`listener`):
```yaml
services:
- name: obfs4-bridge
  addr: :8080
  listener:
    type: obfs4
    metadata:
      nodeId: "0123456789abcdef0123456789abcdef01234567"
      privateKey: "base64-encoded-curve25519-private-key"
      iatMode: 0
  handler:
    type: auto
```

**Client** (`hop node`):
```yaml
chains:
- name: obfs4-chain
  hops:
  - nodes:
    - addr: bridge.example.com:8080
      dialer:
        type: obfs4
        metadata:
          cert: "base64-encoded-server-cert"
          iatMode: 0
      connector:
        type: http
```

### follow existing patterns exactly
- Same `init()` registration pattern
- Same `metadata` struct + `parseMetadata()` pattern
- Same `mdutil.GetString/GetInt` helpers for metadata extraction
- Same listener wrapper chain (proxyproto → metrics → stats → admission → traffic limiter → conn limiter)
- Same dialer factory + Handshake pattern

## Risks

1. **Library API stability**: The refraction-networking/obfs4 library is used by the Tor anti-censorship community. API changes are unlikely but possible. Mitigation: pin to a specific version in go.mod.

2. **State directory requirement**: The library requires a state directory for replay filter persistence. For stateless deployments (containers), we'll default to a temp directory that's cleaned up on exit.

3. **Interop with real Tor obfs4 bridges**: This should work since we're using the same protocol implementation library that Tor uses.

## Verification

1. Build: `cd x && go build ./...` and `cd gost && go build ./cmd/gost/...`
2. Vet: `cd x && go vet ./...`
3. Smoke test: Create a minimal config with obfs4 listener + handler, verify the binary starts without error
4. Integration test: Start a server with obfs4 listener and client with obfs4 dialer, verify connectivity. This can't be tested with real Tor bridges without credentials, but local loopback testing validates the integration layer.
