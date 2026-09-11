# Pass verified mTLS client cert identity to auther plugins

**Issue:** [go-gost/gost#884](https://github.com/go-gost/gost/issues/884) — When a TLS listener with mTLS (`caFile`) is used, pass the verified client certificate's CN, SANs, and fingerprint to the auther plugin (gRPC and HTTP) so external authorization can use certificate-based identity.

## Context

Currently, the `AuthenticateRequest` proto/JSON sent to auth plugins only carries `{username, password, client, service}`. With an mTLS listener, the handler receives a `*tls.Conn` (embedded in wrapper layers), but never extracts or forwards the verified client certificate. The cert identity is invisible to auth plugins.

## Approach

Use **context propagation** — the simplest path: extract TLS peer cert from the connection after the TLS handshake completes (during `http.ReadRequest`), store in `context.Context`, and have auth plugin implementations extract it when building their requests.

This requires zero changes to the `auth.Authenticator` interface, zero changes to the HTTP handler's `Authenticate.Authenticate()` method in auth.go, and zero changes to call sites.

## Files to modify

### 1. `x/ctx/value.go` — Add PeerCert context type

Add a `PeerCert` struct and context get/set helpers, following the existing pattern (`Sid`, `ClientID`, etc.):

```go
type peerCertKey struct{}

type PeerCert struct {
    CN          string
    SANs        []string  // DNSNames + EmailAddresses + URI strings
    Fingerprint string   // SHA-256 hex of cert.Raw
}

func ContextWithPeerCert(ctx context.Context, cert *PeerCert) context.Context {
    return context.WithValue(ctx, peerCertKey{}, cert)
}

func PeerCertFromContext(ctx context.Context) *PeerCert {
    v, _ := ctx.Value(peerCertKey{}).(*PeerCert)
    return v
}
```

### 2. `x/ctx/value_test.go` — Add PeerCert tests

Add tests following the existing test patterns (set/get, empty, wrong-type, nil).

### 3. `x/handler/http/handler.go` — Extract TLS cert info in Handle()

In `Handle()`, save the raw conn before `conn = stats_wrapper.WrapConn(conn, &pStats)` (line 357). After `http.ReadRequest(br)` succeeds (line 382; TLS handshake is now complete), call a private unwrap+extract helper. If a verified peer cert is found, store in context:

```go
// At the top of Handle(), before stats wrapping (currently line 357):
rawConn := conn

// ... (existing code: stats_wrapper.WrapConn, checkRateLimit, bufio, ReadRequest) ...

// After http.ReadRequest succeeds (currently after line 382), TLS handshake is done:
if peerCert := getTLSPeerCert(rawConn); peerCert != nil {
    ctx = xctx.ContextWithPeerCert(ctx, peerCert)
}
```

Add at the bottom of the file (a private function, not exported):

```go
// getTLSPeerCert extracts the verified mTLS client certificate identity from
// a connection by walking wrapper layers (traffic limiter, etc.) to reach the
// underlying *tls.Conn, then reading ConnectionState().VerifiedChains.
// It returns nil if the connection has no TLS peer certificate.
func getTLSPeerCert(conn net.Conn) *xctx.PeerCert {
    for {
        if tc, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
            cs := tc.ConnectionState()
            if cs.HandshakeComplete && len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
                cert := cs.VerifiedChains[0][0]
                fpr := sha256.Sum256(cert.Raw)
                sans := make([]string, 0, len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.URIs))
                sans = append(sans, cert.DNSNames...)
                sans = append(sans, cert.EmailAddresses...)
                for _, u := range cert.URIs {
                    sans = append(sans, u.String())
                }
                return &xctx.PeerCert{
                    CN:          cert.Subject.CommonName,
                    SANs:        sans,
                    Fingerprint: hex.EncodeToString(fpr[:]),
                }
            }
            return nil
        }
        if uw, ok := conn.(interface{ UnwrapConn() net.Conn }); ok {
            conn = uw.UnwrapConn()
            continue
        }
        return nil
    }
}
```

This handles both cases from the TLS listener's `Accept()`:
- **No traffic limiter**: `rawConn` is `tlsConn{*tls.Conn}` → `ConnectionState()` found on first iteration.
- **Traffic limiter enabled**: `rawConn` is `limitConn{tlsConn{*tls.Conn}}` → the unwrap loop peels `limitConn`, then finds `ConnectionState()`.

New imports: `crypto/sha256`, `crypto/tls`, `encoding/hex`. `crypto/tls` is already imported in many handler packages for sniffing; add it here.

### 4. `x/auth/plugin/grpc.go` — Forward PeerCert in AuthenticateRequest

In `Authenticate()`, extract `PeerCert` from context before building the proto request:

```go
if v := xctx.PeerCertFromContext(ctx); v != nil {
    req.ClientCn = v.CN
    req.ClientSan = v.SANs
    req.ClientCertFingerprint = v.Fingerprint
}
```

Add the proto fields to the `AuthenticateRequest` literal.

### 5. `x/auth/plugin/http.go` — Forward PeerCert in JSON request

Same pattern as gRPC — extract from context, populate additional fields in `httpPluginRequest`.

Add to `httpPluginRequest`:
```go
ClientCn              string   `json:"clientCn,omitempty"`
ClientSan             []string `json:"clientSan,omitempty"`
ClientCertFingerprint string   `json:"clientCertFingerprint,omitempty"`
```

### 6. `plugin/auth/proto/auth.proto` — Add new fields

```protobuf
message AuthenticateRequest {
    string username = 1;
    string password = 2;
    string client = 3;
    string service = 4;
    string client_cn = 5;
    repeated string client_san = 6;
    string client_cert_fingerprint = 7;
}
```

### 7. `plugin/auth/proto/auth.pb.go` — Regenerate

Run protoc from the `plugin/auth/proto/` directory:
```
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    auth.proto
```

## What is NOT changed

- `core/auth/auth.go` — interface unchanged
- `x/handler/http/auth.go` — `Authenticate.Authenticate()` method unchanged
- Other handlers (SOCKS5, relay, etc.) — extracting PeerCert is opt-in per handler; only HTTP for now
- Other handlers (SOCKS5, relay, etc.) — extracting PeerCert is opt-in per handler; only HTTP for now
- The `getTLSPeerCert` unwrap loop handles all known wrapper layers generically: `limitConn` (traffic limiter), `serverConn` (conn limiter), `quotaConn` (quota limiter) — all implement `UnwrapConn() net.Conn`. If a future wrapper layer doesn't implement `UnwrapConn()`, the loop returns nil (no cert info), which is the safe default.
- `stats_wrapper.conn` and `xnet.readWriteConn` wrap the conn further but we save `rawConn` *before* these wrappings, so the unwrap loop doesn't need to handle them.
- The `tlsConn` type from `x/internal/util/tls/listener.go` embeds `*tls.Conn`, so `ConnectionState()` is promoted and found by the interface check.

## Review findings (已修复)

1. **`ConnectionState()` interface check fails through `limitConn`** — The TLS listener's `Accept()` wraps `tlsConn` in `limitConn` when a traffic limiter is configured. `limitConn` implements `UnwrapConn()` but NOT `ConnectionState()`. Fixed by replacing the direct interface check with an unwrap loop in `getTLSPeerCert()`.

2. **No new file needed** — The Plan agent proposed `x/internal/util/tls/cert.go` as a reusable helper. Since only the HTTP handler needs this for now, a private function in handler.go is the smaller diff. Can extract later if other handlers adopt it.

3. **`VerifiedChains` vs `PeerCertificates`** — Using `VerifiedChains[0][0]` (Go's verified chain leaf) rather than `PeerCertificates[0]` (all presented certs, potentially unverified). Correct: `VerifiedChains` only contains certs that passed `tls.RequireAndVerifyClientCert` validation.

## Verification

1. **Build check**: `cd x && go build ./...` — verify compilation of all modified packages
2. **Vet check**: `cd x && go vet ./...`
3. **Proto build**: `cd plugin && go build ./...` — verify proto changes compile
4. **Proto regeneration**: Run protoc, verify `.pb.go` generated correctly
5. **Context tests**: `cd x && go test ./ctx/ -v -run PeerCert` — new tests pass
6. **Full workspace**: `cd /config/workspace/go-gost && go build ./...` — no breakage

### Manual verification (config-driven)

Create a test config with an mTLS TLS listener + HTTP handler + auth plugin, and verify that the auth request includes `client_cn`, `client_san`, and `client_cert_fingerprint`. This would use the existing e2e test infrastructure in `gost/tests/e2e/`.
