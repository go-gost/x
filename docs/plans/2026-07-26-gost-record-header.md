# Plan: Client-Controlled HTTP/WS Recording with Three Levels

## Context

The GOST server unconditionally records HTTP/WS traffic. The client needs per-request control
with three granularity levels.

## Design

**Header**: `Gost-Record` with three values (case-insensitive) (matches `Gost-Sid`, `Gost-Forwarded-Node` convention):
| Value | Behavior |
|-------|----------|
| *(absent)* or `full` | Full recording: metadata + body (existing behavior) |
| `headers` | Metadata only: method, URL, status, headers. Skip body/payload capture. |
| `off` | No recording at all. |

**Field**: `RecordMode string` on `HandlerRecorderObject` (`json:"-"`).

**Central guard** (`Record()`): `RecordMode == "off"` → skip entirely.
**Body guard** (all capture sites): `RecordMode == "headers" || RecordMode == "off"` → skip body.

**Per-request**: Set `ro.RecordMode` after cloning `ro` from the request header.
Each request independently controls its own recording level.
**Header stripped** before forwarding.

## Files to Modify (8 files)

### 1. `x/recorder/recorder.go` — RecordMode field + guard

Add field:
```go
RecordMode string `json:"-"` // "" = full, "headers" = metadata only, "off" = no recording
```

Update `Record()`:
```go
func (p *HandlerRecorderObject) Record(ctx context.Context, r recorder.Recorder) error {
    if p == nil || r == nil || p.Time.IsZero() || p.RecordMode == "off" {
        return nil
    }
    // ... existing logic unchanged
}
```

### 2. `x/handler/tunnel/entrypoint/ephttp.go` — httpRoundTrip

After ro clone, parse header:
```go
if v := req.Header.Get("Gost-Record"); v != "" {
    ro.RecordMode = strings.ToLower(v)
}
req.Header.Del("Gost-Record")
```
Body capture: `opts.HTTPBody && ro.RecordMode != "headers" && ro.RecordMode != "off"` (lines 199, 252)

### 3. `x/handler/tunnel/entrypoint/epwebsocket.go` — copyWebsocketFrame

Body capture: `opts.HTTPBody && ro.RecordMode != "headers" && ro.RecordMode != "off"` (line 123)

### 4. `x/handler/http/proxy.go` — proxyRoundTrip

Same header parse as #2. Strip alongside existing proxy header stripping.
Body capture: `!ro.NoRecord` → `ro.RecordMode != "headers" && ro.RecordMode != "off"` (lines 180, 229)

### 5. `x/handler/http/websocket.go` — copyWebsocketFrame

Body capture: same pattern (line 105)

### 6. `x/internal/util/sniffing/sniffer_http.go` — httpRoundTrip

Same header parse + strip before `req.Write(cc)`.
Body capture: same pattern (lines 204, 264)

### 7. `x/internal/util/sniffing/sniffer_ws.go` — copyWebsocketFrame

Body capture: same pattern (line 108)

### 8. `x/internal/util/sniffing/sniffer_h2.go` — h2Handler.ServeHTTP

Same header parse + strip.
Body capture: same pattern (lines 142, 172)

## Propagation (unchanged from original design)

```
httpRoundTrip/proxyRoundTrip (clone ro, set RecordMode)
  → handleUpgradeResponse (receives cloned ro)
    → sniffingWebsocketFrame (clones: *ro2 = *ro)
      → copyWebsocketFrame (RecordMode propagates via clone)
        → ro.Record() → guarded by RecordMode
```

## Edge Cases

- **TLS passthrough / relay protocol**: No HTTP request. No header to check. Unaffected.
- **Handler `Handle()` outer deferred**: `ro.Time` zeroed before dispatch for HTTP paths. Unaffected.

## Verification

```bash
cd x && go build ./... && go vet ./...
```
