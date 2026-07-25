# failCodes — HTTP Status-Based Node Fail Marking

## Context

When GOST acts as HTTP reverse proxy (e.g. LLM API gateway), the upstream
backend can return HTTP 5xx/429 errors while the node itself is healthy at
the transport level. The existing Marker + FailFilter only catches dial-time
failures — there is no way to mark a node unhealthy based on HTTP response
codes.

`failCodes` adds a node-level HTTP setting defining which response status
codes trigger node marking. Cooldown is handled by the existing
`failTimeout`/`maxFails` selector config. No Marker interface changes needed.
No retry — the response is always relayed to the client as-is; marking only
affects subsequent node selection.

## Design

### 1. `core/chain/node.go` — `FailCodes` type

```go
// FailCodes lists response status codes that mark the node as failed.
// Codes < 100 are wildcard hundred-level prefixes (e.g. 5 → 5xx).
type FailCodes []int

func (fc FailCodes) Match(statusCode int) bool {
    for _, code := range fc {
        if (code < 100 && statusCode/100 == code) || statusCode == code {
            return true
        }
    }
    return false
}
```

`HTTPNodeSettings` gets one new field:
```go
FailCodes FailCodes
```

### 2. `x/config/config.go` — config struct

```go
// in HTTPNodeConfig:
FailCodes string `yaml:"failCodes,omitempty" json:"failCodes,omitempty"`
```

Plain comma-separated string — simpler than the original array-of-objects
approach, consistent with the "single string value" metadata convention.

### 3. `x/config/parsing/node/parse.go` — parsing

```go
func parseFailCodes(s string, log logger.Logger) chain.FailCodes {
    var codes chain.FailCodes
    for _, part := range strings.Split(s, ",") {
        part = strings.TrimSpace(part)
        if len(part) == 3 && strings.HasSuffix(part, "xx") {
            if prefix, err := strconv.Atoi(part[:1]); err == nil && prefix > 0 {
                codes = append(codes, prefix) // < 100 → wildcard
                continue
            }
        } else if code, err := strconv.Atoi(part); err == nil && code >= 100 {
            codes = append(codes, code)
            continue
        }
        log.Warnf("failCodes: invalid token %q", part)
    }
    return codes
}
```

Wired inside the `if cfg.HTTP != nil` block in `ParseNode`:
```go
if v := strings.TrimSpace(cfg.HTTP.FailCodes); v != "" {
    settings.FailCodes = parseFailCodes(v, nodeLogger)
}
```

### 4. `x/internal/util/forwarder/sniffer_http.go` — runtime

In `httpRoundTrip`, after `ro.HTTP.StatusCode = resp.StatusCode`:

```go
// failCodes: a matching upstream status marks the node failed so the
// selector's FailFilter skips it. The response still relays to the client;
// closing the connection makes the next client request re-select a node.
if hts := node.Options().HTTP; hts != nil && hts.FailCodes.Match(resp.StatusCode) {
    log.Warnf("failCodes matched status %d for node %s", resp.StatusCode, node.Name)
    if marker := node.Marker(); marker != nil {
        marker.Mark()
    }
    shouldClose = true
}
```

No early return — the response writes through to the client normally.
`shouldClose = true` closes the upstream connection after this request so the
next client request triggers a fresh `hop.Select()`.

## YAML Example

```yaml
chains:
  - name: llm-chain
    hops:
      - name: llm-hop
        selector:
          strategy: round
          maxFails: 1
          failTimeout: 15s
        nodes:
          - name: deepseek-proxy
            addr: api.deepseek.com:443
            connector: {type: http}
            http:
              failCodes: "429,502,503,504"
```

**Important**: `maxFails: 1` is recommended. The `dial()` function calls
`marker.Reset()` on successful TCP dials, which can wipe HTTP-based marks
before `maxFails` is reached. With `maxFails: 1`, one `Mark()` immediately
excludes the node.

## Scope

- **Implemented**: sniffer-based forwarder path (`forward/local`,
  `forward/remote`).
- **Future work**: HTTP handler direct path (`x/handler/http/proxy.go`).
- **No retry**: retry without idempotency knowledge is unsafe — the response
  is always relayed to the client for the client to decide.

## What's NOT changed

- `core/selector/` — Marker/FailFilter untouched
- `core/hop/` — Select() untouched
- `x/chain/router.go` — Router.Dial untouched
- `x/handler/http/proxy.go` — httpHandler direct path (future work)

## Verification

```bash
cd core && go build ./... && go vet ./...
cd x    && go build ./... && go vet ./...
```
