# Plan: Tor SOCKS5 Resolve Commands (go-gost/gost#524)

## Context

Issue [#524](https://github.com/go-gost/gost/issues/524) requests support for Tor-specific SOCKS5 extension commands:

- **`0xF0` RESOLVE** — resolve a hostname to an IP address via Tor's DNS
- **`0xF1` RESOLVE_PTR** — reverse DNS lookup (IP → hostname) via Tor's DNS

This allows tools like `torsocks` and `tor-resolve` to work through GOST when forwarding to a Tor SOCKS5 upstream proxy. Previously, GOST's SOCKS5 handler didn't recognize these commands (returning `CmdUnsupported`), so Tor-specific tools failed to work through GOST.

### Existing extension pattern

GOST already defines custom SOCKS5 extension commands in `x/internal/util/socks/socks.go`:
- `CmdMuxBind = 0xF2` — multiplex bind
- `CmdUDPTun = 0xF3` — UDP tunnel over TCP

We add `CmdResolve = 0xF0` and `CmdResolvePTR = 0xF1` to match the same pattern.

### Data flow

```
Client (torsocks) -> GOST SOCKS5 handler (CMD=0xF0) -> Chain -> SOCKS5 connector (CMD=0xF0 to Tor) -> Tor -> reply
                                                                                                               |
Client <- GOST SOCKS5 handler (writes Reply with resolved IP) <- chain conn (carries resolved addr metadata)
```

Unlike CONNECT (continuous bidirectional pipe), RESOLVE/PTR is a single request-reply exchange. The connector sends the resolve command upstream, reads the reply containing the resolved address, and returns a connection carrying that address as metadata. The handler extracts it, writes the reply to the client, and closes.

## Files to modify

### 1. `x/internal/util/socks/socks.go` — Add Tor resolve command constants

Add after `CmdUDPTun`:
```go
CmdResolve    uint8 = 0xF0  // Tor RESOLVE (hostname -> IP)
CmdResolvePTR uint8 = 0xF1  // Tor RESOLVE_PTR (IP -> hostname)
```

### 2. `x/ctx/value.go` — Add context key for SOCKS5 command override

Add a context key and helpers so the handler can signal a custom SOCKS5 command to the connector. Follows the existing pattern used by other context values in this file (Hash, ClientID, SrcAddr, etc.).

```go
type socks5CmdKey struct{}

func ContextWithSocks5Cmd(ctx context.Context, cmd uint8) context.Context {
    return context.WithValue(ctx, socks5CmdKey{}, cmd)
}

func Socks5CmdFromContext(ctx context.Context) (uint8, bool) {
    v, ok := ctx.Value(socks5CmdKey{}).(uint8)
    return v, ok
}
```

### 3. `x/connector/socks/v5/connector.go` — Send custom SOCKS5 command when signaled

In `Connect()` at the point where `gosocks5.NewRequest(gosocks5.CmdConnect, &addr)` is created:
- Check `Socks5CmdFromContext(ctx)` for a custom command
- Use the context-specified command if present, otherwise default to `CmdConnect`
- After reading the reply, if the command was a resolve type, return a `resolveConn` wrapping the raw connection with the resolved address stored as metadata

### 4. `x/connector/socks/v5/resolve.go` (new file) — Define `resolveConn`

```go
type resolveConn struct {
    net.Conn
    resolvedAddr *gosocks5.Addr
}

func (c *resolveConn) Metadata() mdata.Metadata {
    return mdata.NewMetadata(map[string]any{
        "resolvedAddr": c.resolvedAddr,
    })
}
```

Implements `net.Conn` (passing through to underlying connection) plus `metadata.Metadatable` to expose the resolved address.

### 5. `x/handler/socks/v5/handler.go` — Add resolve command cases

In `Handle()` switch on `req.Cmd`, add:
```go
case socks.CmdResolve:
    return h.handleResolve(ctx, conn, address, ro, log)
case socks.CmdResolvePTR:
    return h.handleResolvePTR(ctx, conn, address, ro, log)
```

### 6. `x/handler/socks/v5/resolve.go` (new file) — Implement resolve handlers

**`handleResolve`**:
1. If `enableTor` metadata is false, return `CmdUnsupported` reply
2. Set context with `socks.CmdResolve` via `ContextWithSocks5Cmd`
3. Call `h.options.Router.Dial(ctx, "tcp", address)` — chain routes to SOCKS5 connector, which sends CMD=0xF0
4. Type-assert returned conn to `md.Metadatable`, extract resolved addr
5. Write `gosocks5.Reply{Rep: Succeeded, Addr: resolvedAddr}` to client conn
6. Close chain connection

**`handleResolvePTR`**: Same structure but uses `socks.CmdResolvePTR`.

Both follow the existing error-handling patterns (log errors, write failure replies to client).

### 7. `x/handler/socks/v5/metadata.go` — Add `enableTor` metadata option

Add a boolean metadata field (keys: `"tor"`, `"enableTor"`, `"socks5.tor"`) that defaults to `false`. When `false`, Tor resolve commands are rejected with `CmdUnsupported`. When `true`, the handler accepts and forwards them.

## Verification

### Build check
```bash
cd /config/workspace/go-gost/x && go build ./... && go vet ./...
```

### Integration test
1. Start GOST with `-L "socks5://127.0.0.1:19055?tor=true" -F "socks5://127.0.0.1:9050"` (pointing at a Tor daemon)
2. Use a SOCKS5 client to send a RESOLVE (0xF0) request to port 19055
3. Verify the reply contains a valid resolved IP address

### Manual testing
```bash
gost -L "socks5://127.0.0.1:19055?tor=true" -F "socks5://127.0.0.1:9050"
tor-resolve example.com 127.0.0.1:19055
```

### Test areas
- `tor=false` (default) rejects 0xF0/0xF1 commands with `CmdUnsupported`
- `tor=true` accepts them and forwards through the chain
- Connector sends correct command byte (0xF0/0xF1) when context signals it
- Connector returns `resolveConn` with correct resolved address in metadata
