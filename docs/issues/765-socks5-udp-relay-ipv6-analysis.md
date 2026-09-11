# go-gost/gost#765 — IPv6 TPROXY UDP fails through SOCKS5 with `relay=udp`

**Status**: Open, `NeedsInvestigation`
**Reported**: 2025-08-19
**Reporter**: @przemyslaw0

## Summary

When GOST uses TPROXY (`redu` listener) to intercept IPv6 UDP traffic and forwards it through a SOCKS5 proxy chain with `relay=udp`, responses never come back — `outputBytes: 0` for all sessions, DNS queries time out.

## Reproduction

```
gost -L "redu://:1111?netns=ns-a" -F "socks5://127.0.0.1:1080?relay=udp"
```

TPROXY-intercepted IPv6 DNS packets (`[2606:4700:4700::1001]:53`) forwarded through 3proxy SOCKS5 server. DNS queries time out with no response data.

## Root Cause

The primary bug is in `relayUDP()` at `x/connector/socks/v5/connector.go:216`. When `relay=udp` is used (standard SOCKS5 UDP ASSOCIATE per RFC 1928), GOST does not handle the server's relay bind address correctly.

### Bug: Wildcard relay address not substituted

When 3proxy returns `0.0.0.0:0` as the relay endpoint (visible in 3proxy logs: `UDPMAP 0.0.0.0:0`), GOST dials directly to this literal address:

```go
// connector.go:216
cc, err := opts.Dialer.Dial(ctx, "udp", reply.Addr.String())
```

This creates a UDP socket "connected" to `0.0.0.0:0`, which is not a usable destination. Per RFC 1928 practice, when the SOCKS5 server returns a wildcard address (`0.0.0.0` or `[::]`), the client should substitute it with the TCP connection's remote address (the SOCKS5 server's actual address).

**Compare with GOST's own SOCKS5 server** in `x/handler/socks/v5/udp.go:63`, which correctly substitutes the wildcard:

```go
saddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
```

The client-side `relayUDP()` does NOT perform this substitution — it uses `reply.Addr` verbatim.

### Additional concern: earlier IPv6 address corruption

In an earlier test (2024-07-11, [3proxy/3proxy#560](https://github.com/3proxy/3proxy/issues/560#issuecomment-2224053601)), the user noted "The IPv6 address received by 3proxy from GOST is received incomplete." The address `2606:4700:4700::1001` arrived as `4700::1001:0:0:53` — a 2-byte left shift of the raw bytes, suggesting possible SOCKS5 UDP header encoding/parsing issues.

In the later test (2025-08-19, the go-gost issue), the address in the 3proxy log appears correct (`2606:4700:4700::1001:53`), though it's ambiguous whether the `:53` is the port or part of the address. This may have been fixed in a GOST version update, or the corruption was a 3proxy log formatting issue.

## Evidence from Logs

**GOST log** (session lifecycle):
- Receives TPROXY UDP from `[fd00::2]:59871` → `[2606:4700:4700::1001]:53`
- `src: 127.0.0.1:42587` — the outbound relay socket's local address (IPv4, expected)
- `inputBytes: 40, outputBytes: 0` — sent 40-byte DNS query, received 0 bytes back
- `duration: 30s` — timed out

**3proxy log**:
- `127.0.0.1:53888 2606:4700:4700::1001:53 40 0 0 UDPMAP 0.0.0.0:0`
- Received 40 bytes from client, returned 0 bytes to client
- Relay bound to `0.0.0.0:0` (wildcard)

## Data Flow Trace

```
dig @2606:4700:4700::1001
  │
  ▼ (TPROXY intercepts IPv6 UDP)
redu listener (::1:1111)
  │ conn.LocalAddr() = [2606:4700:4700::1001]:53
  │ conn.RemoteAddr() = [fd00::2]:59871
  ▼
handler.redirect/udp → Router.Dial(ctx, "udp", "[2606:4700:4700::1001]:53")
  │
  ▼ chain: socks5://127.0.0.1:1080?relay=udp
TCP connect to 127.0.0.1:1080
  │ SOCKS5 handshake
  ▼
socks5Connector.relayUDP()
  │ sends CmdUdp (0x03) with nil address
  │ receives reply: bind = 0.0.0.0:0   ← WILDCARD
  ▼
opts.Dialer.Dial(ctx, "udp", "0.0.0.0:0")  ← BUG: dials to wildcard
  │ creates IPv4 UDP socket connected to 0.0.0.0:0
  ▼
udpRelayConn.WriteTo(data, [2606:4700:4700::1001]:53)
  │ wraps in SOCKS5 UDP header (correct IPv6 ATYP=4)
  │ sends via c.udpConn.Write() → to 0.0.0.0:0  ← goes nowhere useful
  ▼
outputBytes: 0 — no response received
```

## Key Files

| File | Role |
|------|------|
| `x/connector/socks/v5/connector.go` | `relayUDP()` — the buggy method (line 195-234) |
| `x/connector/socks/v5/conn.go` | `udpRelayConn` — SOCKS5 UDP encapsulation (ReadFrom/WriteTo) |
| `x/handler/socks/v5/udp.go` | GOST's own SOCKS5 server `handleUDP()` — has correct wildcard substitution |
| `gosocks5/socks5.go` | SOCKS5 protocol: `Addr`, `UDPHeader`, `UDPDatagram` encoding |
| `x/handler/redirect/udp/handler.go` | Redu handler — TPROXY UDP forwarding |
| `x/listener/redirect/udp/listener_linux.go` | Redu listener — Linux TPROXY socket handling |

## Proposed Fix

In `relayUDP()` at `x/connector/socks/v5/connector.go`, after receiving the SOCKS5 UDP ASSOCIATE reply (line 213), substitute wildcard addresses:

```go
// After reply is read and verified
bindAddr := reply.Addr

// Per RFC 1928: if server returns 0.0.0.0 or [::], substitute
// with the TCP connection's remote address (the SOCKS5 server).
if bindAddr.Host == "0.0.0.0" || bindAddr.Host == "::" {
    host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
    bindAddr.Host = host
}

log.Debugf("bind on: %v", bindAddr)
cc, err := opts.Dialer.Dial(ctx, "udp", bindAddr.String())
```

## Workaround

Use GOST's proprietary UDP tunnel mode (default, without `relay=udp`), which tunnels SOCKS5-encapsulated UDP datagrams over the existing TCP connection. This avoids the separate UDP relay socket entirely:

```
gost -L "redu://:1111?netns=ns-a" -F "socks5://127.0.0.1:1080"
```

**Caveat**: This uses GOST's proprietary `CmdUDPTun` (0xF3), which 3proxy does NOT support. For 3proxy specifically, the `relay=udp` fix is required.
