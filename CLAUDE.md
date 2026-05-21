# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## Build & Verify

```bash
cd x && go build ./...     # verify compilation
cd x && go vet ./...       # static analysis
cd x && go build ./... && go vet ./...   # both
```

There are no tests in this module. Build + vet is the verification path.

## Architecture

`x/` is the **implementation layer** for the GOST proxy framework. Every interface defined in `core/` is implemented here. The module ties the whole system together: it provides ~25 handler implementations, ~25 listener implementations, ~20 dialer implementations, ~15 connector implementations, plus config parsing, registry management, and all cross-cutting concerns.

### Component pattern (applies to every handler, listener, dialer, connector)

Every component follows this exact pattern:

```go
// 1. init() self-registration via blank import
func init() {
    registry.HandlerRegistry().Register("http", NewHandler)
}

// 2. Private struct holding options + parsed metadata
type httpHandler struct {
    md      metadata
    options handler.Options
}

// 3. Functional options constructor
func NewHandler(opts ...handler.Option) handler.Handler {
    options := handler.Options{}
    for _, opt := range opts {
        opt(&options)
    }
    return &httpHandler{options: options}
}

// 4. Init extracts typed values from generic metadata
func (h *httpHandler) Init(md md.Metadata) error {
    return h.parseMetadata(md)
}
```

Each component package also defines a private `metadata` struct and a `parseMetadata(md)` method that uses `mdutil.GetBool/GetInt/GetString/GetDuration(md, keys...)` to extract configuration. Metadata keys are lowercased and multiple fallback keys are tried (e.g., `"observePeriod"`, `"observer.period"`, `"observer.observePeriod"`).

### Config parsing and service composition

`config/parsing/service/parse.go` is the critical wiring function. `ParseService(cfg)` does:

1. Defaults listener type to `"tcp"`, handler type to `"auto"`
2. Sets up TLS config, network namespace, authentication, admission, bypass
3. Looks up the listener and handler factories from their registries, calls them with composed options
4. Creates a `service.Service` (which runs the accept loop calling `handler.Handle` per connection)
5. Wraps the listener in order: proxyproto → metrics → stats → admission → traffic limiter → connection limiter

Each config sub-package (`config/parsing/{auth,bypass,admission,chain,hop,limiter,...}/`) has a `parse.go` that converts config structs into registry lookups and constructed objects.

### Metadata system (`metadata/`)

`metadata.NewMetadata(map[string]any)` wraps a raw config map. All keys are lowercased on lookup. The `mdutil` package (`metadata/util/`) provides typed accessors used everywhere:

- `mdutil.GetBool(md, keys...)`, `GetInt`, `GetFloat`, `GetString`, `GetStrings`
- `mdutil.GetDuration(md, keys...)` — int values treated as seconds; strings parsed with `time.ParseDuration`
- `mdutil.GetStringMap(md, keys...)`, `GetStringMapString`

Metadata key constants are defined in `config/parsing/parse.go` (e.g., `MDKeyProxyProtocol`, `MDKeySoMark`, `MDKeyInterface`, `MDKeyEnableStats`).

### Internal packages (`internal/`)

**Do not import from external modules.** Go's `internal/` restriction enforces this. Key internal packages:

| Package | Purpose |
|---------|---------|
| `internal/ctx/` | Context values for session state during requests |
| `internal/io/` | Custom IO readers/writers |
| `internal/loader/` | `Loader`, `Lister`, `Mapper` interfaces for hot-reloadable components |
| `internal/matcher/` | Pattern matching utilities |
| `internal/net/` | Network utilities (resolver, dialer, proxyproto, HTTP helpers, UDP listener) |
| `internal/plugin/` | External plugin process management |
| `internal/util/sniffing/` | Protocol sniffing (TLS, HTTP, WebSocket) |
| `internal/util/stats/` | Connection stats tracking |
| `internal/util/tls/` | TLS config loading, cert management |
| `internal/util/ws/` | WebSocket utilities |

### Context propagation (`ctx/`)

`x/ctx/value.go` provides typed context key/value helpers used to pass per-request data through the handler chain:

- `ContextWithSid` / `SidFromContext` — Session ID
- `ContextWithSrcAddr` / `SrcAddrFromContext` — Source address
- `ContextWithDstAddr` / `DstAddrFromContext` — Destination address
- `ContextWithClientID` / `ClientIDFromContext` — Client ID (for hash-based load balancing)
- `ContextWithHash` / `HashFromContext` — Hash source for selector

### Hot-reloadable components

Auth, bypass, admission, hosts, ingress, limiter, recorder, router, and SD components all support periodic reload from file/redis/http sources. The pattern:

1. Options include `fileLoader`, `redisLoader`, `httpLoader` plus a `period` duration
2. A background goroutine runs `periodReload(ctx)` calling `loader.Load()` on each tick
3. The component swaps its internal data structure (e.g., `ipMatcher`, `hostMatcher`) atomically

### Listener wrapper ordering

Listeners wrap `net.Listener` in a fixed order. Getting this wrong breaks metrics/admission/limiting:
```
proxyproto → metrics → stats → admission → traffic_limiter → conn_limiter → (protocol-specific)
```

### Registry

All registries are in `x/registry/registry.go` — a single file with ~25 typed global singletons backed by `sync.Map`. Each is accessed via an exported function (e.g., `registry.HandlerRegistry()`, `registry.ListenerRegistry()`). Registration returns `ErrDup` on name collision; empty names are silently ignored.

### Selectors (`selector/`)

Load-balancing strategies for hops and chain groups:

| Strategy | Behavior |
|----------|----------|
| `RoundRobinStrategy` | Atomic counter, modulo selection |
| `RandomStrategy` | Weighted random using `RandomWeighted` |
| `FIFOStrategy` | Always first element (stickiness) |
| `HashStrategy` | CRC32 of client ID or hash context value |

Filters (`FailFilter`, `BackupFilter`) are applied before the strategy, reducing the candidate pool.

### API (`api/`)

Uses Gin framework. Registers CRUD endpoints under `/config` for all component types. Supports basic auth when an auther is configured. Swagger docs at `/docs`.

### Metrics (`metrics/`)

Prometheus-style metrics following `_total`, `_seconds` naming conventions. Constants for all metric names (e.g., `MetricServiceRequestsCounter`, `MetricNodeConnectDurationObserver`). `Enable(bool)` toggles globally. When disabled, `GetCounter/Gauge/Observer` return noop implementations.
