# Skip Authentication for Whitelisted Client IPs

## Context

Issue go-gost/gost#881 requests a `skipauth` metadata option that allows client IPs/networks (CIDR) to bypass authentication. Currently users needing this must run two services (one with auth, one without + admission + iptables DNAT), which is needlessly complex.

## Approach

Wrap the `auth.Authenticator` at service-parse time with a `WhitelistedAuthenticator` that checks the client IP (from context's `SrcAddr`) against the skipauth CIDR/IP list before delegating to the real auther. This covers ALL handlers transparently — HTTP, SOCKS4/5, relay, http2, SSH — since the wrapping happens in `ParseService` before the auther is injected.

### Files to create

**`x/auth/whitelist.go`** — `WhitelistedAuthenticator` wrapper type
- `NewWhitelistedAuthenticator(auther auth.Authenticator, patterns []string)` — parses patterns as IPs and CIDRs, builds two matchers
- `Authenticate(ctx, user, password, opts...)` — extracts `SrcAddr` from context, checks IP against matchers; if matched returns `("", true)` to skip auth; otherwise delegates to real auther

### Files to modify

**`x/config/parsing/service/parse.go`** — parse `skipauth` from handler metadata, wrap auther
- After line 303 (after auther group is built), before handler construction (line 349)
- Read `skipauth` from `cfg.Handler.Metadata`: try `GetStrings` first (YAML list), then fall back to comma-split `GetString` (URL query format)
- If non-empty and auther is set, wrap with `WhitelistedAuthenticator`

### Key details

| Aspect | Details |
|--------|---------|
| Matchers | Reuse `matcher.IPMatcher` + `matcher.CIDRMatcher` from `x/internal/matcher/` (same infrastructure as admission control) |
| Context | `xctx.SrcAddrFromContext(ctx)` provides the client IP; established in service loop before handler.Handle() |
| Config formats | YAML: `handler.metadata.skipauth: ["10.0.0.0/8", "192.168.1.1"]`; URL: `?skipauth=10.0.0.0/8,192.168.1.1` |
| Handlers covered | All handlers using `handler.AutherOption(auther)` — HTTP, SOCKS4/5, HTTP2, relay, SSH |
| Nil auther edge case | If no auther is configured but skipauth is set, whitelisted clients pass auth; non-whitelisted fail auth (returns false) — user mistake, but consistent behavior |

### Wire format for comma-separated URL values

The URL query `?skipauth=10.0.0.0/8,192.168.1.1` is stored in metadata as a single string. `mdutil.GetStrings` does not handle plain strings, so add explicit comma-splitting in ParseService:
```go
if ss := mdutil.GetStrings(hmd, "skipauth"); len(ss) > 0 {
    skipauth = append(skipauth, ss...)
} else if s := mdutil.GetString(hmd, "skipauth"); s != "" {
    for _, p := range strings.Split(s, ",") {
        if p = strings.TrimSpace(p); p != "" {
            skipauth = append(skipauth, p)
        }
    }
}
```

## Verification

```bash
cd /config/workspace/go-gost/x
go build ./... && go vet ./...
go test ./...
```
