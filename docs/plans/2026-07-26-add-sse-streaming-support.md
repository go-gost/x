# Add SSE Streaming Rewrite Support to HTTP Sniffer

## Context

The HTTP sniffer forwarder (`x/internal/util/forwarder/`) needs to support
**streaming rewrite** for SSE (Server-Sent Events, `Content-Type: text/event-stream`)
responses. The use case is protocol conversion (e.g., Anthropic API ↔ OpenAI API)
via the rewriter plugin (`core/rewriter.Rewriter`), where each SSE event's data
payload must be transformed before reaching the client.

### Current behavior

- **SSE without rewrite/record:** `resp.Write(rw)` uses `io.Copy` internally to
  stream the body — works correctly for basic proxying.
- **SSE + record:** `NewBody` wraps the body for recording, `resp.Write` streams,
  partial capture is stored. Works, but misleading (incomplete capture).
- **SSE + rewrite:** `rewriteRespBody` exits early (`ContentLength <= 0` guard at
  `sniffer_rewrite.go:45`) — the rewriter is never called. This is the gap.
- **Request body rewrite:** `rewriteReqBody` also exits early on `ContentLength <= 0`.
  Non-streaming API requests (OpenAI → Anthropic) have a finite body and work fine.

### Approach

**SSE response body:** A new `io.ReadCloser` wrapper that reads SSE events from
the upstream body, applies the rewrite chain per-event, and returns rewritten
bytes via `Read()`. SSE is line-delimited: events separated by `\n\n`. Each event
is a self-contained message that can be independently rewritten.

**Non-streaming response/request body:** The existing `rewriteRespBody` /
`rewriteReqBody` already work for finite JSON bodies. No changes needed.

**Rewriter plugin server:** A standalone process (separate from sniffer) that
implements the `rewriter.Rewriter` interface via HTTP/gRPC. It handles:
- OpenAI request JSON → Anthropic request JSON
- Anthropic response JSON → OpenAI response JSON
- Anthropic SSE event bytes → OpenAI SSE event bytes (each event is independent)

## Changes

### 1. New file: `x/internal/util/forwarder/sniffer_sse.go`

**`isStreamingResponse(resp *http.Response) bool`** — returns `true` when
`Content-Type` starts with `"text/event-stream"`.

**`newSSERewriteBody(src io.ReadCloser, rewrites []chain.HTTPBodyRewriteSettings, contentType string) io.ReadCloser`** —
returns an `io.ReadCloser` that:
1. Uses `bufio.Scanner` with a custom `SplitFunc` that splits on `\n\n`
   (handles both `\n\n` and `\r\n\r\n`)
2. For each scanned SSE event token, applies the rewrite chain (same logic as
   `rewriteRespBody` in `sniffer_rewrite.go`):
   - Content-Type filter from `rewrite.Type`
   - Plugin rewriter: `rewrite.Rewriter.Rewrite(ctx, event)` if pattern matches
     or no pattern set
   - Regex replacement: `rewrite.Pattern.ReplaceAll(event, replacement)` if
     no plugin rewriter
3. Rewritten event + `\n\n` terminator written to internal `bytes.Buffer`
4. `Read()` returns from this buffer
5. On upstream EOF, any remaining buffered data (incomplete final event) is
   flushed as-is

**Edge cases:**
- Empty events (`\n\n\n\n`): pass through for each `\n\n`, no rewrite call
- Incomplete final event (no trailing `\n\n`): forwarded as-is when upstream closes
- No rewrites configured: `newSSERewriteBody` not called (guard in httpRoundTrip)
- `Content-Encoding` set: skip (same guard as `rewriteRespBody`)
- Plugin returns `error` or `nil` data: log warning, pass original event through

### 2. Modify `x/internal/util/forwarder/sniffer_http.go` — `httpRoundTrip()`

Insert **two guards** before `rewriteRespBody` call (line 449):

```go
// If the response is text/event-stream with body rewrites, switch to streaming
// rewrite: wrap resp.Body to rewrite each SSE event individually.
if isStreamingResponse(resp) && len(respBodyRewrites) > 0 {
    resp.Body = newSSERewriteBody(resp.Body, respBodyRewrites, resp.Header.Get("Content-Type"))
}
```

The existing flow after this is untouched:
- `rewriteRespBody` at line 449: returns nil immediately due to `ContentLength <= 0`
- `NewBody` wrapping at line 454: wraps the SSE rewrite wrapper for recording
- `resp.Write(rw)` at line 457/461: streams rewritten events to client

### 3. No changes needed (rationale)

| File | Reason |
|------|--------|
| `x/internal/util/forwarder/sniffer_h2.go` | H2 handler uses `http.ResponseWriter` + `io.Copy` but has no rewrite support at all. SSE rewrite here is out of scope for this implementation. |
| `x/internal/util/forwarder/sniffer_rewrite.go` | `rewriteRespBody`/`rewriteReqBody` unchanged — they handle finite bodies only. `ContentLength <= 0` guard correct. |
| `core/rewriter/rewriter.go` | Interface `Rewriter.Rewrite(ctx, []byte) → ([]byte, error)` fits both non-streaming and per-event SSE rewrite. |
| `x/rewriter/plugin/grpc.go` / `http.go` | Plugin clients are agnostic to body content. No changes. |
| `core/chain/node.go` | `HTTPBodyRewriteSettings` / `HTTPNodeSettings` — all fields sufficient. |
| `x/config/parsing/` | Config parsing already wires rewriter plugins into nodes. |

### 4. Tests — `x/internal/util/forwarder/sniffer_test.go`

**`TestNewSSERewriteBody`** — unit test:
- SSE events rewritten by plugin rewriter (data: line replacement)
- SSE events with regex replacement
- Multiple rewrite rules applied sequentially
- Empty events pass through
- Incomplete final event flushed on close
- No rewrites (pass-through)

**`TestRewriteRespBody_SSE_ContentType`** — verify `rewriteRespBody` skips
`text/event-stream` (already tested by `TestRewriteRespBody_NegativeContentLength`
but add explicit test with proper content type).

### 5. Rewriter Plugin Server (separate from sniffer)

Located in `llm-api-converter/` (already exists):
- `cmd/root.go` — CLI flag parsing (`--addr`, `--model`, `--max-tokens`)
- `main.go` — entry point calling `rewriter.ListenAndServe()`
- `convert/convert.go` — `Convert(data []byte, opts) → ([]byte, error)`:
  - Parse content type or detect format from JSON structure
  - OpenAI request → Anthropic request conversion
  - Anthropic response (non-streaming) → OpenAI response
  - Anthropic SSE event bytes → OpenAI SSE event bytes
- `convert/types.go` — request/response types for both APIs
- `rewriter/server.go` — HTTP plugin server (accepts POST /rewrite)
- `rewriter/server_test.go` — validates all conversion paths

The plugin server is an external process started separately from gost. The sniffer
connects to it via the rewriter plugin client.

**Config example** (in gost YAML):
```yaml
rewriters:
- name: api-converter
  plugin:
    type: http   # or grpc
    addr: "127.0.0.1:8000"
```

## Files modified

| File | Change |
|------|--------|
| `x/internal/util/forwarder/sniffer_sse.go` | **NEW** — `isStreamingResponse()`, `newSSERewriteBody()` |
| `x/internal/util/forwarder/sniffer_http.go` | Add SSE body wrapping guard in `httpRoundTrip()` |
| `x/internal/util/forwarder/sniffer_test.go` | SSE rewrite tests |

## Verification

```bash
cd x && go build ./internal/util/forwarder/
cd x && go vet ./internal/util/forwarder/
cd x && go test ./internal/util/forwarder/ -v -run 'TestNewSSERewriteBody|TestRewriteRespBody' -count=1
```
