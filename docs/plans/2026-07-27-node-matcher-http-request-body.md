# Node matcher: HTTP request body matcher

## Context

GOST's node matcher ([x/routing/matcher.go](../../../x/routing/matcher.go)) routes requests to specific proxy nodes via a rule string (e.g. `Host("api.example.com") && Method("POST")`). It matches on `ClientIP`, `Host`, `Network`, `Proto`, `Method`, `Path`, `Query`, `Header` — but **not** the request body. A user wants to route on request body content (e.g. an OpenAI-style JSON body containing `"model":"gpt-4"`), which is impossible today.

The body must be available *before* node selection (the matcher runs inside `hop.Select`) and still forwarded afterward. HTTP-level select options (`Method`/`Path`/`Query`/`Header`) are populated in **one place only**: the forwarder/sniffer path at [sniffer_http.go:183-191](../../../x/internal/util/forwarder/sniffer_http.go#L183-L191) (transparent-proxy / TCP-forward-with-sniffing). The regular HTTP proxy handler doesn't populate them; the HTTP/2 sniffer doesn't either. This change is scoped to the HTTP/1.x sniffer path — consistent with current behavior.

Decisions confirmed with the user:
- Add a single **`BodyRegexp(regex)`** matcher keyword (one arg). Realistic use cases are regex over structured bodies (JSON). Substring/exact can be added later.
- Body reading is **opt-in per node** via a new `matcher.bodySize` field, sibling of `matcher.priority`. The forwarder reads up to the **max `bodySize` across all candidate nodes** in the hop before selection, restores the stream, and passes the prefix to the matcher. Nodes that don't set `bodySize` (the default) pay zero overhead.

## Approach

Seven small layers, each following an existing pattern in the touched file. The key invariant: the matcher tree knows nothing about body size — size is plain data on the node, aggregated by the hop, read by the forwarder.

### 1. Carry the body prefix — [core/routing/matcher.go](../../../core/routing/matcher.go)

Add `Body []byte` to `Request` (size-capped prefix read by the forwarder; nil/empty when no node opts in or the request is bodyless).

### 2. Plumb body through hop selection — [core/hop/hop.go](../../../core/hop/hop.go)

- Add `Body []byte` to `SelectOptions`.
- Add `BodySelectOption(body []byte) SelectOption` (mirrors `HeaderSelectOption`).
- Define a small optional interface for size aggregation:
  ```go
  // BodySizer returns the max request body size (bytes) needed by node matchers
  // in this hop, so callers holding the request body (e.g. the forwarder
  // sniffer) can pre-read a sized prefix before selection. Returns 0 if no node
  // needs body matching.
  type BodySizer interface { BodySize() int }
  ```

### 3. Per-node size on node options — [core/chain/node.go](../../../core/chain/node.go)

- Add `MatcherBodySize int` to `NodeOptions` ([line 85](../../../core/chain/node.go#L85)).
- Add `MatcherBodySizeNodeOption(int) NodeOption`.
- Add a public cap constant `MaxMatcherBodySize = 1 << 20` (1MB), consistent with the recorder's body cap. The parser clamps to it.

### 4. Forward Body + expose hop size — [x/hop/hop.go](../../../x/hop/hop.go)

- At [line 177](../../../x/hop/hop.go#L177), add `Body: options.Body,` to the `routing.Request{}` literal in `chainHop.Select`.
- Implement `BodySize() int` on `*chainHop`: iterate `p.Nodes()` under RLock, return `max(node.Options().MatcherBodySize)`. This is the implementation of `hop.BodySizer` that the forwarder type-asserts for. (Plugin/wrapped hops don't implement it → no body matching through them; acceptable, documented.)

### 5. The matcher — [x/routing/matcher.go](../../../x/routing/matcher.go)

- Add `bodyRegexp(tree, args...)`: compile the regex once at parse time (modelled on `pathRegexp`); at request time return false if `req.Body` is empty, else `re.Match(req.Body)`.
- Register `"BodyRegexp": expectNParameters(bodyRegexp, 1)` in the `httpFuncs` map. Registering the keyword is the only config-side change needed to make it usable in rule strings (rules are free-form strings parsed via `routing.NewMatcher` at [node/parse.go:201](../../../x/config/parsing/node/parse.go#L201)).
- Add `TestMatcherBodyRegexp` in [x/routing/matcher_test.go](../../../x/routing/matcher_test.go): match, no-match, empty body → false, invalid regex fails at parse time.

### 6. Per-node config field — [x/config/config.go:425](../../../x/config/config.go#L425) + [x/config/parsing/node/parse.go:197](../../../x/config/parsing/node/parse.go#L197)

- Add `BodySize int` to `NodeMatcherConfig` (sibling of `Rule` and `Priority`):
  ```go
  // BodySize is the max request body bytes made available to BodyRegexp
  // matchers. 0 (default) disables body reading for this node. Capped at
  // chain.MaxMatcherBodySize. Only takes effect under an HTTP sniffing handler.
  BodySize int `yaml:",omitempty" json:"bodySize,omitempty"`
  ```
- In the existing `if cfg.Matcher != nil` block in `node/parse.go`, apply the parsed (and clamped) value: `chain.MatcherBodySizeNodeOption(clampMatcherBodySize(cfg.Matcher.BodySize))`, where `clampMatcherBodySize` is a tiny helper bounding to `[0, chain.MaxMatcherBodySize]`.
- Add a test in [x/config/parsing/node/parse_test.go](../../../x/config/parsing/node/parse_test.go) asserting the field is parsed and clamped.

### 7. Read + restore the body — [x/internal/util/forwarder/sniffer_http.go](../../../x/internal/util/forwarder/sniffer_http.go)

Inside `resolveHTTPNode` (the single function used by both the initial dial and the keep-alive re-dial path), before `ho.hop.Select(...)`:
```go
node = &chain.Node{}
if ho.hop != nil {
    var bodyPrefix []byte
    if bs, ok := ho.hop.(hop.BodySizer); ok {
        if size := bs.BodySize(); size > 0 && req.Body != nil {
            bodyPrefix, _ = io.ReadAll(io.LimitReader(req.Body, int64(size)))
            req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyPrefix), req.Body))
        }
    }
    node = ho.hop.Select(ctx,
        hop.ClientIPSelectOption(clientIP),
        hop.ProtocolSelectOption(sniffing.ProtoHTTP),
        hop.HostSelectOption(host),
        hop.MethodSelectOption(req.Method),
        hop.PathSelectOption(req.URL.Path),
        hop.QuerySelectOption(req.URL.Query()),
        hop.HeaderSelectOption(req.Header),
        hop.BodySelectOption(bodyPrefix),
    )
}
```
`MultiReader` restores the stream so `httpRoundTrip`'s later `req.Write(cc)` still forwards the full body unchanged — Content-Length / chunked encoding stay valid because the bytes are reproduced in order. For bodyless requests (GET/HEAD), `req.Body` is `http.NoBody` → `ReadAll` returns empty immediately → negligible overhead.

No changes to: forwarder `sniffer.go` (no new `HandleOptions`), forward handler `metadata.go` / `sniffing.go` (no per-handler knob), HTTP/2 sniffer, or the regular HTTP proxy handler.

### Out of scope

- HTTP/2 sniffer path ([sniffer_h2.go](../../../x/internal/util/forwarder/sniffer_h2.go)) — doesn't populate `Method`/`Path`/etc. today.
- Regular HTTP proxy handler ([x/handler/http/](../../../x/handler/http/)) — doesn't populate HTTP-level select options today.
- Plugin/wrapped hops — don't implement `hop.BodySizer`, so they skip body reading (`BodyRegexp` returns false). Acceptable.

## Example config

```yaml
services:
- name: ...
  handler:
    type: tcp        # forward with HTTP sniffing
    metadata:
      sniffing: true
  listener: ...
  forwarder:
    nodes:
    - name: gpt4-node
      addr: ...
      matcher:
        rule: 'Method("POST") && Path("/v1/chat/completions") && BodyRegexp(`"model"\s*:\s*"gpt-4"`)'
        bodySize: 65536   # opt-in; 0 (default) disables body reading
        priority: 10
    - name: default-node
      addr: ...
```

## Verification

1. `cd x && go build ./... && go vet ./...` — compiles across the workspace.
2. `cd x && go test -race ./routing/... ./hop/... ./config/parsing/node/... ./internal/util/forwarder/...` — new tests pass; existing tests unaffected. Set `CGO_ENABLED=1` for `-race`.
3. Manual e2e: a `play/`-style forward+sniff config with two nodes whose `BodyRegexp` rules partition POST bodies by a JSON field, with `matcher.bodySize` set; send two `curl -d` POSTs with different bodies and confirm each routes to the correct node (verify via the debug log line `"node %s match request ..."` at [x/hop/hop.go:190](../../../x/hop/hop.go#L190), or per-node metrics counters). Confirm a large upload (>bodySize) still forwards correctly after the prefix read, and that a GET (no body) is unaffected.
