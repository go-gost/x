# Plan: Add matcher + probe to chainGroup

## Problem

`chainGroup` currently only chains by name string with a selector — no matcher-based
filtering or health-check probing. `hopGroup` (already implemented in 4c2748b) has both.
This treats chains and hops asymmetrically: users who manage multiple upstream proxy
paths (chains) get no way to route by hostname or exclude dead chains.

## How it works (hopGroup pattern)

`x/hop/group.go`:
- `HopEntry` wraps a `hop.Hop` + optional `routing.Matcher` + optional `*chain.ProbeConfig`
  + independent `selector.Marker`
- `hopGroup.Select()` filters entries by matcher, runs the group selector over eligible
  entries, delegates to the winning entry's underlying hop
- Entries with probes get a goroutine: selects a node from the hop, dials/handshakes/probes

`x/config/config.go` `ForwardHopGroupConfig`:
```go
type ForwardHopConfig struct {
    Hop     string             `yaml:",omitempty" json:"hop,omitempty"`
    Matcher *NodeMatcherConfig `yaml:",omitempty" json:"matcher,omitempty"`
    Probe   *ProbeConfig       `yaml:",omitempty" json:"probe,omitempty"`
}
```

## Plan

### 1. Config types — `x/config/config.go`

Change `Chains` from `[]string` to `[]*ChainGroupEntry` — the new struct handles
both plain strings (old format) and structured entries (new format) via custom
`UnmarshalYAML` / `UnmarshalJSON`:

```go
type ChainGroupEntry struct {
    Chain   string             `yaml:",omitempty" json:"chain,omitempty"`
    Matcher *NodeMatcherConfig `yaml:",omitempty" json:"matcher,omitempty"`
    Probe   *ProbeConfig       `yaml:",omitempty" json:"probe,omitempty"`
}

// UnmarshalYAML accepts either a plain string ("chain-a") or an object.
func (e *ChainGroupEntry) UnmarshalYAML(value *yaml.Node) error {
    var s string
    if value.Decode(&s) == nil {
        e.Chain = s
        return nil
    }
    type alias ChainGroupEntry // avoid recursion
    return value.Decode((*alias)(e))
}

// UnmarshalJSON accepts either a plain string or an object.
func (e *ChainGroupEntry) UnmarshalJSON(data []byte) error {
    var s string
    if json.Unmarshal(data, &s) == nil {
        e.Chain = s
        return nil
    }
    type alias ChainGroupEntry
    return json.Unmarshal(data, (*alias)(e))
}

type ChainGroupConfig struct {
    Chains   []*ChainGroupEntry  `yaml:",omitempty" json:"chains,omitempty"`
    Selector *SelectorConfig     `yaml:",omitempty" json:"selector,omitempty"`
}
```

Backward compat — both of these work:

```yaml
# Old: plain strings → each decoded as ChainGroupEntry{Chain: "..."}
chainGroup:
  chains:
    - chain-a
    - chain-b
  selector:
    strategy: round
```

```yaml
# New: structured entries
chainGroup:
  chains:
    - chain: chain-a
      matcher:
        rule: Host(`example.com`)
      probe:
        type: tcp
        interval: 10s
    - chain: chain-b
  selector:
    strategy: round
```

### 2. Chain entry type — `x/chain/group.go` (new file)

Mirrors `x/hop/group.go`:

```go
type ChainEntry struct {
    chain   chain.Chainer
    matcher routing.Matcher
    probe   *chain.ProbeConfig
    marker  selector.Marker
}

func NewChainEntry(c chain.Chainer, m routing.Matcher, probe *chain.ProbeConfig) *ChainEntry

// Route delegates to the underlying chain — implements chain.Chainer so the
// entry itself can be passed to the selector (and selected via FailFilter).
func (e *ChainEntry) Route(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Route {
    return e.chain.Route(ctx, network, address, opts...)
}

func (e *ChainEntry) Marker() selector.Marker   // implements selector.Markable
```

### 3. Enhanced chainGroup — `x/chain/chain.go`

Current:
```go
type chainGroup struct {
    chains   []chain.Chainer
    selector selector.Selector[chain.Chainer]
}
```

New:
```go
type chainGroup struct {
    entries    []*ChainEntry
    selector   selector.Selector[chain.Chainer]
    logger     logger.Logger
    cancelFunc context.CancelFunc
}
```

`chains` is dropped — `NewChainGroup` wraps each bare chain as a `ChainEntry`
(no matcher, no probe). There is only one data path: `entries`.

New/updated methods:

**`NewChainGroup(chains ...chain.Chainer)`** — wraps each chain as
`&ChainEntry{chain: c, marker: selector.NewFailMarker()}`. Backward compat:
existing callers get a bare entry with no matcher/probe.

**`WithGroupEntries(entries ...*ChainEntry)`** — replaces `entries` with
fully populated entries (matchers + probes). Callers that need the old
behavior pass entries via the constructor; callers with matchers/probes use
this setter. The constructor still works standalone when only bare chains
are needed.

**`selectChain()` —** single path, iterates `entries`:

```go
func (p *chainGroup) selectChain(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Chainer {
    var options chain.RouteOptions
    for _, opt := range opts { opt(&options) }
    req := routing.Request{
        Network: network,
        Host:    options.Host,
    }

    // Stage 1: matcher filter — build eligible pool.
    var eligible []chain.Chainer
    for _, e := range p.entries {
        if e.matcher != nil && !e.matcher.Match(&req) {
            continue
        }
        eligible = append(eligible, e) // *ChainEntry as chain.Chainer
    }
    if len(eligible) == 0 {
        return nil
    }
    if len(eligible) == 1 {
        return eligible[0]
    }
    // Stage 2: selector (FailFilter + strategy).
    return p.selector.Select(ctx, eligible...)
}
```

**`Route()` —** unchanged pattern, delegates to `selectChain` then
`chain.Route()`.

**Probe methods** — identical pattern to hopGroup:
- `runEntryProbe(ctx, e)` — ticker loop
- `probeEntry(e, cfg)` — cmd probe or TCP/HTTP through chain's Route

For chain probes, TCP/HTTP types use `e.chain.Route()` + `route.Dial()` to reach
the probe target (ProbeConfig.Addr). CMD probe runs a shell command.

**`Close()`** — stops probe goroutines, closes entries.

### 4. Config parsing — `x/config/parsing/service/parse.go`

`group.Chains` is now `[]*ChainGroupEntry` — no separate `Entries` field. The
parser always iterates `group.Chains`, and each entry may or may not have
matcher+probe (plain strings decode as entries with only `Chain` set).

Update `chainGroup()`:

```go
func chainGroup(name string, group *config.ChainGroupConfig, log logger.Logger) chain.Chainer {
    // Collect chains: from 'name' param and from group.Chains (or group is nil).
    var entries []*xchain.ChainEntry

    if c := registry.ChainRegistry().Get(name); c != nil {
        entries = append(entries, xchain.NewChainEntry(c, nil, nil))
    }
    if group != nil {
        for _, ge := range group.Chains {
            c := registry.ChainRegistry().Get(ge.Chain)
            if c == nil {
                log.Warnf("chain %q not found in chainGroup, skipping", ge.Chain)
                continue
            }
            var m routing.Matcher
            if ge.Matcher != nil && ge.Matcher.Rule != "" {
                m, err = xrouting.NewMatcher(ge.Matcher.Rule)
                if err != nil {
                    log.Warnf("chain %q: bad matcher rule: %v, skipping", ge.Chain, err)
                    continue
                }
            }
            entries = append(entries, xchain.NewChainEntry(c, m, node_parser.ParseProbeConfig(ge.Probe)))
        }
    }
    if len(entries) == 0 {
        return nil
    }
    sel := selector_parser.ParseChainSelector(group.Selector)
    if sel == nil {
        sel = selector_parser.DefaultChainSelector()
    }
    return xchain.NewChainGroup().
        WithGroupEntries(entries...).
        WithSelector(sel).
        WithGroupLogger(log.WithFields(...))
}
```

Update callers to pass logger (both use `log` from ParseService scope):
- line 207: `chainGroup(cfg.Listener.Chain, cfg.Listener.ChainGroup, log)`
- line 383: `chainGroup(cfg.Handler.Chain, cfg.Handler.ChainGroup, log)`

## Files changed

| File | Change |
|------|--------|
| `x/config/config.go` | Change `Chains` from `[]string` to `[]*ChainGroupEntry`; add `ChainGroupEntry` struct with custom `UnmarshalYAML`/`UnmarshalJSON` |
| `x/chain/group.go` | NEW — `ChainEntry` type, `NewChainEntry`, matcher+probe logic |
| `x/chain/chain.go` | Add entries/log/cancel to `chainGroup`, `WithGroupEntries`, `WithGroupLogger`, updated `Route`/`next`, `Close`, probe methods |
| `x/config/parsing/service/parse.go` | Update `chainGroup()` to parse `ChainGroupEntry` with matcher+probe, pass logger |

## What the matcher can use at chain level

`chain.RouteOptions` only carries `Host`. So chain-level matchers can match on:
- `Host()` — the destination hostname
- `ClientIP()` — available from context via ClientIP in ctx

If full HTTP-level matching (Method, Path, Header, Body) is needed at the chain
level in the future, `RouteOptions` in `core/chain/chain.go` can be extended.
For now the available fields handle the common "route host X through chain Y" case.

## Probe behavior for chain entries

- **TCP/HTTP probe**: uses `e.chain.Route(ctx, "tcp", cfg.Addr)` to get a route,
  then `route.Dial()` to reach the probe target. Tests the chain end-to-end.
- **CMD probe**: runs a shell command (same as hopGroup).
- The probe marks the entry's independent `selector.Marker` on failure, so the
  chain is excluded from selection by `FailFilter` until it recovers.

## Known gap: `Close()` caller

`chainGroup.Close()` cancels the probe context and stops goroutines, but there
is no obvious caller in the current codebase. `hopGroup.Close()` works because
it cascades through `Chain.Close() → hop.Close() → hopGroup.Close()` — chain
groups don't sit inside a `Chain`, so this path doesn't exist for them.

This is a pre-existing gap (hopGroup has the same problem when not inside a
`Chain`). Goroutines survive until the probe context is cancelled. Not blocking
this plan — worth a follow-up to have the router close its chainer on shutdown.

## Verification

- `cd x && go build ./... && go vet ./...`
- Spot-check: old config with `chains: ["a", "b"]` still parses (each string → `ChainGroupEntry{Chain: "a"}`)
- Spot-check: new config with `chains: [{chain: "a", matcher: {rule: Host(`foo`)}, probe: {type: tcp}}]` parses correctly
