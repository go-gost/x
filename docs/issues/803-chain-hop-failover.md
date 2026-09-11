# Fix gost#803: Chain silently bypasses failed hops

## Context

Issue: [go-gost/gost#803](https://github.com/go-gost/gost/issues/803) — When all nodes in a chain hop are unreachable, GOST silently truncates the chain and routes traffic through only the remaining hops or falls back to direct dial. This is a **security concern**: users think traffic is going through the full proxy chain but it's being silently bypassed.

Maintainer response (Oct 2025): "后面会增加控制参数" (will add a control parameter later). No fix implemented yet.

### Root Cause Chain (4 interacting bugs)

1. **`Chain.Route()` returns a truncated route** ([x/chain/chain.go:134-136](x/chain/chain.go#L134-L136)): When `h.Select()` returns nil (no usable node in a hop), the method returns the partial route with only nodes from previous hops — not nil. This means the caller can't detect that hops are missing.

2. **`Router.dial()` only falls back when route is nil** ([x/chain/router.go:142-144](x/chain/router.go#L142-L144)): The check `if route == nil { route = DefaultRoute }` fires ONLY for nil routes. Since `Chain.Route()` never returns nil for a partial route, the DirectRoute fallback is only triggered for the all-hops-failed case.

3. **`FailFilter` has `len(vs) <= 1` guard** ([x/selector/filter.go:28-29](x/selector/filter.go#L28-L29)): A single failed node passes through the filter unchanged. This means a hop with 1 node that has been marked as failed still gets selected.

4. **`chainHop.Select()` returns single node directly** ([x/hop/hop.go:202-203](x/hop/hop.go#L202-L203)): When `len(nodes) == 1`, the node is returned immediately — bypassing the selector and its FailFilter entirely.

### User's Configuration (reporter)

```
Service (socks5 :9000) → hop-0 (local Clash socks5 :9001) → hop-1 (2 remote grpc servers, round-robin + failover)
```

When both remote servers in hop-1 are unreachable: hop-0 is selected, hop-1 returns nil → `Chain.Route()` returns route with hop-0 only → traffic flows through Clash only, never reaching the remote servers. **Silent security degradation.**

## Proposed Fix

### Change 1: `Chain.Route()` — return nil on hop failure

**File**: `x/chain/chain.go`

When `h.Select()` returns nil (no eligible node found for a hop), return `nil` instead of the partial `rt`. This signals "no usable route" to the caller.

```go
// Before (line 134-136):
if node == nil {
    return rt
}

// After:
if node == nil {
    return nil
}
```

A nil return from `Chain.Route()` matches the documented contract: "Route builds a route by selecting one node from each hop." If a hop can't provide a node, the route is not built.

### Change 2: `Router.dial()` — error on chain failure instead of direct-dial fallback

**File**: `x/chain/router.go`

When a chain is configured (`r.options.Chain != nil`) but returns nil route, the router should return an error rather than falling back to `DefaultRoute` (direct dial). This prevents the silent bypass.

```go
// Current (line 142-144):
if route == nil {
    route = DefaultRoute
}

// Replace with:
if route == nil {
    if r.options.Chain != nil {
        return nil, fmt.Errorf("no available route: all hops failed")
    }
    route = DefaultRoute
}
```

### Change 3: `FailFilter` — remove `len(vs) <= 1` guard

**File**: `x/selector/filter.go`

Remove the early return that passes through single nodes. A failed node should be filtered regardless of how many candidates exist.

```go
// Before (line 28-30):
if len(vs) <= 1 {
    return vs
}

// Remove this guard entirely.
```

The guard was likely a defensive optimization, but it creates a correctness issue: a single-node hop with that node failed will never be filtered, making failover ineffective for single-node hops.

**Interaction with Change 4**: After removing this guard, `chainHop.Select()` must always go through the selector for the FailFilter to see single-node hops. Change 4 ensures this.

### Change 4: `chainHop.Select()` — always use selector when configured

**File**: `x/hop/hop.go`

The single-node fast path (line 202-203) and the priority short-circuit (lines 210-219) both bypass the selector entirely. When a selector is configured, it should always be called — even for single-node or priority-short-circuit cases — so that FailFilter gets a chance to filter dead nodes.

```go
// Current (line 199-204):
if len(nodes) == 0 {
    return nil
}
if len(nodes) == 1 {
    return nodes[0]
}

// New behavior: if selector exists, always use it.
// Only use the fast path when there's no selector.
if len(nodes) == 0 {
    return nil
}
if s := p.options.selector; s != nil {
    // Always go through selector (applies FailFilter, BackupFilter, strategy)
    return s.Select(ctx, nodes...)
}
if len(nodes) == 1 {
    return nodes[0]
}
```

Additionally, the priority short-circuit (lines 210-219) should also yield to the selector when one is configured.

### Change 5 (Optional): Add `required` field to HopConfig

**Files**: `x/config/config.go`, `x/config/parsing/hop/parse.go`

If backward compatibility with the old "skip failed hops" behavior is desired, add a `Required` field to `HopConfig` and `hop.Options`. When `required: false`, a hop returning nil would be skipped (old behavior). When `required: true` (default), the chain fails if the hop has no nodes.

```go
// HopConfig addition:
type HopConfig struct {
    // ... existing fields ...
    Required *bool `yaml:"required,omitempty" json:"required,omitempty"`
}
```

Default: `required: true` (fail if hop has no nodes). Setting `required: false` restores the old "skip" behavior.

Then in `Chain.Route()`:
```go
if node == nil {
    if h.Options().Required {
        return nil  // fail the chain
    }
    continue  // skip this hop (old behavior)
}
```

However, this adds complexity. For the initial fix, I recommend **Changes 1-4 only** — they fix the core bug for all users. If the maintainer wants the old behavior as an opt-in, Change 5 can be added later.

## Files Modified

| File | Change |
|------|--------|
| `x/chain/chain.go` | `Chain.Route()`: return nil when hop fails |
| `x/chain/router.go` | `Router.dial()`: error when chain fails, don't fall back to direct |
| `x/selector/filter.go` | `FailFilter`: remove `len(vs) <= 1` guard |
| `x/hop/hop.go` | `chainHop.Select()`: always use selector when configured; remove single-node and priority fast paths |

## Verification

1. **Build**: `cd x && go build ./... && go vet ./...`
2. **Existing tests**: `cd x && CGO_ENABLED=1 go test -race ./...`
3. **Specific package tests**: `go test -v ./chain/... ./hop/... ./selector/...`
4. **Manual verification**: Add a test case for the multi-hop chain with failed middle hop scenario:
   - Create a 2-hop chain where hop-1 has a single node that always fails
   - Verify `Chain.Route()` returns nil
   - Verify the router returns an error (not a direct connection)
5. **E2E**: Run relevant e2e tests if available: `go test ./gost/tests/e2e/ -v -timeout 10m`
