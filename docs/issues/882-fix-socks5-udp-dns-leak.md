# Fix SOCKS5 UDP DNS Leak & Hostname Preservation (gost#882)

**Issue**: [go-gost/gost#882](https://github.com/go-gost/gost/issues/882) — two related problems in the SOCKS5 UDP ASSOCIATE path:

1. **DNS leak**: When a SOCKS5 UDP datagram carries ATYP=DOMAINNAME (e.g., `dns.google:53`), `socks.udpConn.ReadFrom()` calls `net.ResolveUDPAddr("udp", ...)` at [x/internal/util/socks/conn.go:131](x/internal/util/socks/conn.go#L131) — always uses system DNS (127.0.0.53), even when `resolver=1.1.1.1` is configured in the handler.

2. **Hostname not passed to relay chain**: Because `ReadFrom` resolves domain→IP immediately, the relay chain receives only the IP. For a setup like `-F relay://...`, the exit relay cannot resolve DNS using its own configured resolver.

## Context

### Affected code path

Client → SOCKS5 handler → `handleUDP()` → `socks.UDPConn(pc1)` → `udp.NewRelay(pc1, pc)` → relay loop:

```
Goroutine 1 (client→upstream):
  pc1.ReadFrom()   → parsed SOCKS5 UDP header, net.ResolveUDPAddr → IP
  pc.WriteTo(data, IP)

Goroutine 2 (upstream→client):
  pc.ReadFrom()   → upstream response
  pc1.WriteTo(data, addr)
```

### Key files

| File | Role |
|------|------|
| [x/internal/util/socks/conn.go](x/internal/util/socks/conn.go) | `udpConn.ReadFrom()` at L131 calls `net.ResolveUDPAddr` — **root cause of DNS leak** |
| [x/handler/socks/v5/udp.go](x/handler/socks/v5/udp.go) | `handleUDP()` at L31 — creates `pc1` (client-facing) and `pc` (upstream), sets up relay |
| [x/handler/socks/v5/metadata.go](x/internal/util/socks/conn.go) | Metadata already has `udpResolveDomain` at L29, used for outbound path only |
| [x/internal/util/relay/conn.go](x/internal/util/relay/conn.go) | `udpTunConn.ReadFrom()` at L57 also resolves via `net.ResolveUDPAddr` — mirror fix |
| [x/internal/net/udp/relay.go](x/internal/net/udp/relay.go) | `Relay.Run()` copies between pc1/pc2 — address from ReadFrom goes to WriteTo as-is |

### Key insight about relay chain vs direct

- **Relay chain** (e.g., `-F relay://...`): `pc` is a `UDPTunClientConn` whose `WriteTo()` calls `gosocks5.Addr.ParseFrom(addr.String())` — naturally preserves domain names as ATYP=Domain in the SOCKS5 UDP header, and the relay server handles resolution.
- **Direct** (no chain): `pc` is `*net.UDPConn`. Writing a domain address to it fails because `net.UDPConn.WriteTo` requires `*net.UDPAddr`.

So the fix is **NOT** to resolve in `ReadFrom` at all, but to let domains pass through naturally for the relay case. For the direct case, wrap `pc` with a resolver.

## Plan

### Step 1: Add custom `domainAddr` type

**File**: [x/internal/util/socks/conn.go](x/internal/util/socks/conn.go)

Add a `domainAddr` type that preserves a hostname as a `net.Addr`:

```go
// domainAddr is a net.Addr that preserves a domain name without resolving it.
// Used when a SOCKS5 UDP datagram carries ATYP=DOMAINNAME to avoid triggering
// DNS resolution via net.ResolveUDPAddr.
type domainAddr struct {
    network string
    host    string
    port    int
}

func (a *domainAddr) Network() string { return a.network }
func (a *domainAddr) String() string  { return net.JoinHostPort(a.host, strconv.Itoa(a.port)) }
```

This type ensures that `addr.String()` returns `"dns.google:53"` instead of `"8.8.8.8:53"`, preserving the hostname for downstream consumers like `UDPTunClientConn.WriteTo`.

### Step 2: Modify `udpConn.ReadFrom()` to not resolve domains

**File**: [x/internal/util/socks/conn.go](x/internal/util/socks/conn.go) — `udpConn.ReadFrom()` (L131), the **client-facing reader** where the leak is.

Replace:

```go
addr, err = net.ResolveUDPAddr("udp", socksAddr.String())
```

With:

```go
if net.ParseIP(socksAddr.Host) != nil {
    addr, err = net.ResolveUDPAddr("udp", socksAddr.String())
} else {
    addr = &domainAddr{network: "udp", host: socksAddr.Host, port: int(socksAddr.Port)}
}
```

If the SOCKS5 address is already an IP (ATYP IPv4/IPv6), return `*net.UDPAddr` as before. If it's a domain, return a `domainAddr` without resolution.

**Do NOT touch `udpTunConn.ReadFrom()`** at [x/internal/util/relay/conn.go:75](x/internal/util/relay/conn.go#L75). That is the *upstream* side — it reads relay-exit response *sources*, which are always resolved IPs. No leak there. Changing it risks reintroducing ATYP=Domain into client-bound responses, breaking the `udpResolveDomain` invariant for clients like tun2proxy/Surge. Add `strconv` to conn.go's imports for `domainAddr.String()`.

### Step 3: Add resolving wrapper for direct connections

**File**: [x/handler/socks/v5/udp.go](x/handler/socks/v5/udp.go)

Add a `resolvePacketConn` wrapper that resolves domain addresses to IPs before writing to the raw socket:

```go
// resolvePacketConn wraps a net.PacketConn and resolves domain addresses to
// IP addresses before writing. Used for direct UDP connections (no relay chain)
// where the underlying socket requires *net.UDPAddr.
type resolvePacketConn struct {
    net.PacketConn
    resolver   resolver.Resolver
    hostMapper hosts.HostMapper
}

func (c *resolvePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
    host, portStr, err := net.SplitHostPort(addr.String())
    if err != nil {
        return c.PacketConn.WriteTo(b, addr)
    }
    if net.ParseIP(host) != nil {
        return c.PacketConn.WriteTo(b, addr)
    }

    var ips []net.IP
    if c.hostMapper != nil {
        ips, _ = c.hostMapper.Lookup(context.Background(), "ip", host)
    }
    if len(ips) == 0 && c.resolver != nil {
        ips, _ = c.resolver.Resolve(context.Background(), "ip", host)
    }
    if len(ips) == 0 {
        ips, _ = net.LookupIP(host)
    }
    if len(ips) == 0 {
        return 0, fmt.Errorf("socks5 udp: cannot resolve %s", host)
    }

    // Prefer IPv4
    ip := ips[0]
    for _, candidate := range ips {
        if candidate.To4() != nil {
            ip = candidate
            break
        }
    }
    port, _ := strconv.Atoi(portStr)
    return c.PacketConn.WriteTo(b, &net.UDPAddr{IP: ip, Port: port})
}
```

This mirrors the existing `domainResolvePacketConn.WriteTo()` (same file, L217-266) but wraps the *upstream* side.

### Step 4: Wire it up in `handleUDP()`

**File**: [x/handler/socks/v5/udp.go](x/handler/socks/v5/udp.go)

**Critical placement:** the `*net.UDPConn` detection MUST happen at the raw cast (line 86), BEFORE `pc = metrics.WrapPacketConn(...)` at line 112 — after the metrics wrap `pc` is always a metrics wrapper, so a late type assertion would always fail.

Insert immediately after the `pc, ok := c.(net.PacketConn)` block (after line 94, before line 112):

```go
// Wrap upstream PC with domain resolution for direct (no-chain) connections.
// Relay-chain connections (udpTunConn) encode domain addrs as ATYP=Domain
// in the SOCKS5 UDP header and let the exit resolve; raw *net.UDPConn.WriteTo
// needs *net.UDPAddr, so domains must be resolved here.
// Always wrap direct conns — udpConn.ReadFrom now returns domainAddr, which
// *net.UDPConn cannot consume; the resolver→system fallback lives inside.
if _, isDirect := pc.(*net.UDPConn); isDirect {
    pc = &resolvePacketConn{
        PacketConn:  pc,
        resolver:    h.options.Router.Options().Resolver,
        hostMapper:  h.options.Router.Options().HostMapper,
    }
}
```

Detection rationale:
- Direct `Router.Dial("udp", "")` returns `*net.UDPConn` (already a PacketConn, returned as-is by the router)
- Any chain (relay/socks5/ss) returns an address-encoding PacketConn (`udpTunConn`, `udpRelayConn`, ...) that preserves domains via `ParseFrom` — not `*net.UDPConn`, so correctly skipped

### Step 5: Backward compatibility notes

- `socks.UDPConn()` signature unchanged — callers unaffected
- Existing `domainResolvePacketConn` still works for the outbound path (upstream→client) when `udpResolveDomain=true`
- The new `resolvePacketConn` handles the inbound path (client→upstream) for direct connections

## Verification

1. **Build check**: `cd x && go build ./... && go vet ./...`
2. **Unit test**: `cd x && go test ./internal/util/socks/` (if tests exist)
3. **Manual e2e scenario**: Setup gost with relay chain:
   ```bash
   # Relay server
   gost -L 'relay://:1111?bind=true&resolver=1.1.1.1'
   
   # SOCKS5 entry
   gost -L 'socks5://:5999?udp=true&resolver=1.1.1.1' -F relay://127.0.0.1:1111
   
   # Send UDP datagram to dns.google:53 via SOCKS5
   # Before: strace shows connect(127.0.0.53) on entry
   # After: no DNS query on entry, resolved at relay exit
   ```
4. **Direct (no chain)**: Verify resolver=1.1.1.1 is used instead of system DNS
   ```bash
   gost -L 'socks5://:5999?udp=true&resolver=1.1.1.1'
   ```
