# Chain-Level Liveness Probe

## Context

GOST currently relies on **reactive failure detection**: nodes are marked failed only when real connection attempts fail. Recovery is passive — `FailFilter` lets nodes back in after `failTimeout` (default 10s). There is no proactive health checking and no latency tracking for informed routing decisions.

The user wants Kubernetes-style liveness probes, but **at the chain level only**. Node-level probes are not applicable because in a multi-hop chain (`client → hop1 → hop2 → target`), intermediate nodes are not directly reachable — they can only be accessed through previous hops. A chain-level probe tests end-to-end connectivity through the entire chain and correctly accounts for this topology.

## Design Overview

The probe is configured on a chain. It periodically dials a configurable TCP address or HTTP endpoint **through the full chain** (using `chain.Route().Dial()`), exercising the exact same code path as real traffic. Results update the chain's existing `selector.Marker` — making `FailFilter` automatically skip unhealthy chains with **zero selector changes**. Probe latency is also tracked for optional latency-aware chain selection strategies.

```
YAML config → ParseChain() → Chain.SetProbe() → background goroutine
                                                      |
                                              ticker loop
                                                  |
                                    chain.Route(probeAddr).Dial()
                                                  |
                                        success → Marker.Reset()
                                        failure → Marker.Mark()
```

## Config Schema

```yaml
chains:
- name: chain-1
  hops:
  - name: hop-1
    nodes:
    - name: proxy1
      addr: 10.0.0.1:1080
      connector:
        type: socks5
      dialer:
        type: tcp
  probe:
    type: tcp              # "tcp" or "http"
    addr: 8.8.8.8:53       # probe target (required for chain-level)
    interval: 30s          # probe interval (default 30s)
    timeout: 10s           # probe timeout (default 10s)
    maxFails: 2            # consecutive failures before marking dead (default 1)

- name: chain-2
  hops:
  - name: hop-2
    ...
  probe:
    type: http
    addr: httpbin.org:80
    httpPath: /get
    httpHost: httpbin.org
    expectedStatus: 200
    interval: 60s
    timeout: 15s
```

For chains in a `chainGroup`, the selector can also use probe latency:

```yaml
services:
- name: service-0
  addr: ":8080"
  handler:
    type: http
    chain: chain-1
    chainGroup:
      chains:
      - chain-2
      - chain-3
      selector:
        strategy: lowestlatency   # prefers lowest probe latency
        maxLatency: 500ms         # filters chains exceeding this threshold
```

## Implementation Plan

### Step 1: Core types — `core/chain/probe.go` (NEW FILE)

```go
// ProbeType enumerates supported probe protocols.
type ProbeType string

const (
    ProbeTypeTCP  ProbeType = "tcp"
    ProbeTypeHTTP ProbeType = "http"
)

// ProbeConfig holds configuration for a chain's liveness probe.
type ProbeConfig struct {
    Type           ProbeType
    Addr           string        // probe target address (required)
    Interval       time.Duration // probe interval
    Timeout        time.Duration // per-probe timeout
    MaxFails       int           // consecutive failures before marking dead
    HTTPPath       string        // HTTP request path (default "/")
    HTTPHost       string        // HTTP Host header
    HTTPHeaders    map[string]string
    ExpectedStatus int           // expected HTTP status (default 200)
}

// ProbeResult holds the outcome of the most recent probe check.
type ProbeResult struct {
    Success   bool
    Latency   time.Duration
    Error     string
    Timestamp time.Time
}

// ProbeResultReader is implemented by types that expose probe results.
// Chain implements this for selector integration.
type ProbeResultReader interface {
    ProbeResult() *ProbeResult
}
```

### Step 2: Extend `x/chain/chain.go`

**Add to `Chain` struct:**
```go
type Chain struct {
    name     string
    hops     []hop.Hop
    marker   selector.Marker
    metadata metadata.Metadata
    logger   logger.Logger

    // NEW: probe support
    probeCfg    *chain.ProbeConfig
    probeResult atomic.Value // stores *chain.ProbeResult
    probeCancel context.CancelFunc
}
```

**Add `ProbeResult()` method** (implements `chain.ProbeResultReader`):
```go
func (c *Chain) ProbeResult() *chain.ProbeResult {
    if v := c.probeResult.Load(); v != nil {
        return v.(*chain.ProbeResult)
    }
    return nil
}
```

**Add `SetProbe(cfg)` method** — starts the background probe goroutine. Called by `ParseChain()` after all hops are added:
```go
func (c *Chain) SetProbe(cfg *chain.ProbeConfig) error {
    c.probeCfg = cfg
    ctx, cancel := context.WithCancel(context.Background())
    c.probeCancel = cancel
    go c.runProbe(ctx)
    return nil
}
```

**Add `Close() error`** — stops the probe goroutine. Makes `Chain` implement `io.Closer` so the registry's `Unregister()` automatically stops probes during config reload:
```go
func (c *Chain) Close() error {
    if c.probeCancel != nil {
        c.probeCancel()
    }
    return nil
}
```

**Add `runProbe()`** — the ticker loop. Follows the existing `periodReload` pattern from `x/bypass/bypass.go`:
```go
func (c *Chain) runProbe(ctx context.Context) {
    interval := c.probeCfg.Interval
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    // Run first probe immediately
    c.probe(ctx)

    for {
        select {
        case <-ticker.C:
            c.probe(ctx)
        case <-ctx.Done():
            return
        }
    }
}

func (c *Chain) probe(ctx context.Context) {
    cfg := c.probeCfg
    timeout := cfg.Timeout
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    start := time.Now()
    route := c.Route(ctx, "tcp", cfg.Addr)
    conn, err := route.Dial(ctx, "tcp", cfg.Addr)
    latency := time.Since(start)

    result := &chain.ProbeResult{Timestamp: time.Now(), Latency: latency}
    if err != nil {
        result.Success = false
        result.Error = err.Error()
        c.marker.Mark()
        c.logger.Warnf("probe failed: %v (latency %v)", err, latency)
    } else {
        conn.Close()
        result.Success = true
        c.marker.Reset()
        c.logger.Debugf("probe success: latency %v", latency)
    }
    c.probeResult.Store(result)
}
```

**Key insight**: The probe uses `c.Route()` + `route.Dial()` — the same path as real traffic through the chain. It updates `c.marker` which is the same marker used by `FailFilter` on chainGroup selectors. Zero selector changes needed for basic liveness.

### Step 3: Probe implementation — `x/internal/probe/` (NEW PACKAGE)

This package provides the HTTP prober variant. The TCP probe is handled inline in the chain since it's trivial (just `route.Dial()` + close). The HTTP prober needs more logic.

**`x/internal/probe/probe.go`**:
```go
// HTTPProber performs an HTTP GET request over an established chain connection.
type HTTPProber struct {
    Path           string
    Host           string
    Headers        map[string]string
    ExpectedStatus int
}

// Probe sends an HTTP GET over conn and validates the response.
func (p *HTTPProber) Probe(conn net.Conn, addr string) error
```

The HTTP prober:
1. Builds URL from `addr` + `Path`
2. Sends `GET <path> HTTP/1.1\r\nHost: <host>\r\n...` over `conn`
3. Reads response, checks status code matches expected
4. Returns error if status mismatch or any I/O error

### Step 4: Config struct — `x/config/config.go`

**Add `ProbeConfig`:**
```go
type ProbeConfig struct {
    Type           string            `json:"type"`           // "tcp" or "http"
    Addr           string            `json:"addr,omitempty"` // probe target address
    Interval       time.Duration     `json:"interval"`
    Timeout        time.Duration     `json:"timeout"`
    MaxFails       int               `json:"maxFails"`       // defaults to 1 (via FailFilter)
    HTTPPath       string            `json:"httpPath,omitempty"`
    HTTPHost       string            `json:"httpHost,omitempty"`
    HTTPHeaders    map[string]string `json:"httpHeaders,omitempty"`
    ExpectedStatus int               `json:"expectedStatus,omitempty"`
}
```

**Add to `ChainConfig`:**
```go
type ChainConfig struct {
    Name     string            `json:"name"`
    Hops     []*HopConfig      `json:"hops"`
    Probe    *ProbeConfig      `json:"probe,omitempty"`      // NEW
    Metadata map[string]any    `json:"metadata,omitempty"`
}
```

### Step 5: Config parsing — `x/config/parsing/chain/parse.go`

In `ParseChain()`, after creating the chain and adding all hops, attach the probe:

```go
func ParseChain(cfg *config.ChainConfig, log logger.Logger) (chain.Chainer, error) {
    // ... existing code: create chain, add hops ...

    if cfg.Probe != nil {
        probeCfg := parseProbeConfig(cfg.Probe, c.Name)
        if probeCfg != nil {
            c.SetProbe(probeCfg)
        }
    }
    return c, nil
}

func parseProbeConfig(cfg *config.ProbeConfig, chainName string) *chain.ProbeConfig {
    if cfg.Addr == "" {
        return nil // address is required for chain-level probe
    }

    interval := cfg.Interval
    if interval <= 0 {
        interval = 30 * time.Second
    }

    timeout := cfg.Timeout
    if timeout <= 0 {
        timeout = 10 * time.Second
    }

    maxFails := cfg.MaxFails
    if maxFails <= 0 {
        maxFails = 1
    }

    expectedStatus := cfg.ExpectedStatus
    if expectedStatus <= 0 {
        expectedStatus = 200
    }

    path := cfg.HTTPPath
    if path == "" {
        path = "/"
    }

    return &chain.ProbeConfig{
        Type:           chain.ProbeType(cfg.Type),
        Addr:           cfg.Addr,
        Interval:       interval,
        Timeout:        timeout,
        MaxFails:       maxFails,
        HTTPPath:       path,
        HTTPHost:       cfg.HTTPHost,
        HTTPHeaders:    cfg.HTTPHeaders,
        ExpectedStatus: expectedStatus,
    }
}
```

### Step 6: HTTP probe support in `Chain.probe()`

Extend the `Chain.probe()` method to handle HTTP type:

```go
func (c *Chain) probe(ctx context.Context) {
    cfg := c.probeCfg
    timeout := cfg.Timeout
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    start := time.Now()
    route := c.Route(ctx, "tcp", cfg.Addr)
    conn, err := route.Dial(ctx, "tcp", cfg.Addr)
    latency := time.Since(start)

    result := &chain.ProbeResult{Timestamp: time.Now(), Latency: latency}

    if err != nil {
        result.Success = false
        result.Error = err.Error()
        c.marker.Mark()
    } else {
        defer conn.Close()

        if cfg.Type == chain.ProbeTypeHTTP {
            err = probe.NewHTTPProber(cfg).Probe(conn, cfg.Addr)
            if err != nil {
                result.Success = false
                result.Error = err.Error()
                c.marker.Mark()
            } else {
                result.Success = true
                c.marker.Reset()
            }
        } else {
            result.Success = true
            c.marker.Reset()
        }
    }
    c.probeResult.Store(result)
}
```

### Step 7: New selector strategy — `x/selector/latency.go` (NEW FILE)

Generic latency-aware selection — works with any `T` implementing `ProbeResultReader`.

**`LatencyFilter`:**
```go
func LatencyFilter[T any](maxLatency time.Duration) selector.Filter[T]
```

Filters out items whose `ProbeResult().Latency > maxLatency` or `ProbeResult().Success == false`. Items without probe results pass through (conservative: don't filter uninstrumented items).

**`LowestLatencyStrategy`:**
```go
func LowestLatencyStrategy[T any]() selector.Strategy[T]
```

Selects the item with the lowest `ProbeResult().Latency`. Items without probe results are sorted last. Items with failed probes are filtered out. Uses `math.MinInt64` for the initial comparison.

To access probe results, both filter and strategy use:
```go
if reader, ok := any(v).(chain.ProbeResultReader); ok {
    result := reader.ProbeResult()
    ...
}
```

`Chain` already implements `ProbeResultReader` via `ProbeResult()` added in Step 2.

### Step 8: Selector config — `x/config/parsing/selector/parse.go`

**Add to `SelectorConfig`:**
```go
type SelectorConfig struct {
    Strategy    string        `json:"strategy"`
    MaxFails    int           `json:"maxFails"`
    FailTimeout time.Duration `json:"failTimeout"`
    MaxLatency  time.Duration `json:"maxLatency,omitempty"` // NEW
}
```

**Extend `ParseChainSelector()`:**
```go
func ParseChainSelector(cfg *config.SelectorConfig) selector.Selector[chain.Chainer] {
    if cfg == nil {
        return nil
    }

    var strategy selector.Strategy[chain.Chainer]
    switch cfg.Strategy {
    case "round", "rr":
        strategy = xs.RoundRobinStrategy[chain.Chainer]()
    case "random", "rand":
        strategy = xs.RandomStrategy[chain.Chainer]()
    case "fifo", "ha":
        strategy = xs.FIFOStrategy[chain.Chainer]()
    case "hash":
        strategy = xs.HashStrategy[chain.Chainer]()
    case "lowestlatency", "lowest", "ll":                    // NEW
        strategy = xs.LowestLatencyStrategy[chain.Chainer]() // NEW
    default:
        strategy = xs.RoundRobinStrategy[chain.Chainer]()
    }

    filters := []selector.Filter[chain.Chainer]{
        xs.FailFilter[chain.Chainer](cfg.MaxFails, cfg.FailTimeout),
        xs.BackupFilter[chain.Chainer](),
    }
    if cfg.MaxLatency > 0 {                                                  // NEW
        filters = append(filters, xs.LatencyFilter[chain.Chainer](cfg.MaxLatency)) // NEW
    }

    return xs.NewSelector(strategy, filters...)
}
```

### Step 9: Registry integration (automatic cleanup)

The chain registry (`x/registry/registry.go`) already calls `Close()` on any registered value that implements `io.Closer` when `Unregister()` is called. During config reload, `unregisterAll(ChainRegistry)` is called, which calls `Unregister()` on each chain — automatically stopping all probe goroutines.

No changes needed to `x/registry/` or `x/config/loader/`.

## File Change Summary

| File | Change |
|------|--------|
| `core/chain/probe.go` | **NEW** — `ProbeType`, `ProbeConfig`, `ProbeResult`, `ProbeResultReader` |
| `x/chain/chain.go` | Add probe fields + `SetProbe()` + `ProbeResult()` + `Close()` + `runProbe()` + `probe()` methods |
| `x/internal/probe/probe.go` | **NEW** — `HTTPProber` struct with `Probe()` method |
| `x/config/config.go` | Add `ProbeConfig` struct; add `Probe` field to `ChainConfig`; add `MaxLatency` to `SelectorConfig` |
| `x/config/parsing/chain/parse.go` | Parse probe config + call `chain.SetProbe()` |
| `x/selector/latency.go` | **NEW** — `LatencyFilter[T]`, `LowestLatencyStrategy[T]` |
| `x/config/parsing/selector/parse.go` | Add `"lowestlatency"` strategy; add `LatencyFilter` when `MaxLatency > 0` |

**Total: 3 new files, 5 modified files. No changes to registry, loader, hop, node, or service parsing.**

## What stays the same (backward compatibility)

- **Zero probe config changes**: No `probe` field → chain has no probe goroutine, no `Close()` behavior change (existing `Close()` is a no-op since `probeCancel` is nil, which is the same as before).
- **Existing `FailFilter`**: Already works with chain's `Marker`. Probes update the same marker — no change needed.
- **Existing selectors**: RoundRobin, Random, FIFO, Hash all work unchanged.
- **All existing YAML configs**: Remain valid.
- **Node/hop parse**: No changes.

## Verification

1. **Build & vet**: `cd x && go build ./... && go vet ./...`
2. **Unit test — TCP probe on chain**:
   - Create a simple chain (direct dial, no proxy hops)
   - Start a local TCP listener on a random port
   - Create a chain with TCP probe pointing at the listener
   - Verify `ProbeResult().Success == true` after first tick
   - Close listener, wait for next tick
   - Verify `ProbeResult().Success == false` and `Marker().Count() > 0`
3. **Unit test — HTTP probe on chain**:
   - Start a local HTTP server with `/health` returning 200
   - Configure chain with HTTP probe
   - Verify success
   - Change server to return 500, verify failure
4. **Unit test — Chain Close stops probe**:
   - Create chain with probe
   - Call `Close()`
   - Verify probe goroutine exits (no more marker updates after close)
5. **Unit test — LowestLatencyStrategy**:
   - Create mock chains with different probe latencies
   - Verify `LowestLatencyStrategy` selects the fastest
6. **Unit test — LatencyFilter**:
   - Create mock chains with various latencies
   - Verify chains exceeding `maxLatency` are filtered out
7. **Integration — chainGroup failover with probe**:
   - Create two chains in a chainGroup, one with a valid probe target and one with an unreachable target
   - Verify the dead chain gets marked and `FailFilter` stops selecting it
   - Verify recovery when the target becomes reachable again
