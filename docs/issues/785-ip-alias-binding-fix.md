# Fix: go-gost/gost#785 — IP Alias Interface Binding (Revised)

## Context

The initial fix (commit `caa82f2`) skipped `SO_BINDTODEVICE` only for loopback interfaces. The user's follow-up comment reveals this is **insufficient** — they also use a custom `ip-aliases` **dummy interface** (not loopback) for IP aliases:

```
3: ip-aliases: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500
    inet 10.2.2.2/32 scope global ip-aliases
    inet 10.1.1.1/32 scope global ip-aliases
    inet6 fc00::beef/128 scope global
```

When `interface: "10.1.1.1"` is specified:
1. `findInterfaceByIP(10.1.1.1)` resolves to `"ip-aliases"` (not `"lo"`)
2. `SO_BINDTODEVICE("ip-aliases")` is called → forces traffic through a dummy interface with no route to external hosts → **fails**

The user also tested with IPs on `lo` (`10.3.3.3`, `fc33::1`) and got `dial tcp: address [fc33::1]:0: no suitable address found` — this is a separate IPv6→IPv4 mismatch issue (expected), not a `SO_BINDTODEVICE` problem.

## Root Cause

When the `interface` config is specified as an **IP address**, GOST resolves it to an interface name and calls `SO_BINDTODEVICE` on that interface. But the user's intent is source IP binding for policy routing, not device binding. `SO_BINDTODEVICE` on a dummy/loopback interface breaks outbound connectivity.

`SO_BINDTODEVICE` is only meaningful when the user specifies an actual interface **name** (like `eth0`) to force traffic through a specific physical NIC.

## Fix: Skip `SO_BINDTODEVICE` when interface was specified as IP

Track whether `ParseInterfaceAddr`'s input was an IP address or an interface name. When it was an IP, skip `SO_BINDTODEVICE` — source IP binding via `LocalAddr` is sufficient for policy routing.

### Files to modify

#### 1. `internal/net/addr.go` — `ParseInterfaceAddr`

Add a boolean `isIP` return value:

```go
func ParseInterfaceAddr(ifceName, network string) (ifce string, addr []net.Addr, isIP bool, err error) {
    if ifceName == "" {
        addr = append(addr, nil)
        return
    }

    ip := net.ParseIP(ifceName)
    if ip == nil {
        // Interface NAME — SO_BINDTODEVICE is meaningful
        isIP = false
        var ife *net.Interface
        ife, err = net.InterfaceByName(ifceName)
        if err != nil {
            return
        }
        var addrs []net.Addr
        addrs, err = ife.Addrs()
        if err != nil {
            return
        }
        if len(addrs) == 0 {
            err = fmt.Errorf("addr not found for interface %s", ifceName)
            return
        }
        ifce = ifceName
        for _, addr_ := range addrs {
            if ipNet, ok := addr_.(*net.IPNet); ok {
                addr = append(addr, ipToAddr(ipNet.IP, network))
            }
        }
    } else {
        // IP ADDRESS — skip SO_BINDTODEVICE, use LocalAddr binding only
        isIP = true
        ifce, err = findInterfaceByIP(ip)
        if err != nil {
            return
        }
        addr = []net.Addr{ipToAddr(ip, network)}
    }
    return
}
```

#### 2. `internal/net/dialer/dialer.go` — `Dial` and `dialOnce`

Pass `bindToDevice` flag through:

In `Dial()` (line ~93-118):
```go
ifces := strings.Split(d.Interface, ",")
for _, ifce := range ifces {
    strict := strings.HasSuffix(ifce, "!")
    ifce = strings.TrimSuffix(ifce, "!")
    var ifceName string
    var ifAddrs []net.Addr
    ifceName, ifAddrs, isIP, err = xnet.ParseInterfaceAddr(ifce, network)
    if err != nil && strict {
        return
    }

    for _, ifAddr := range ifAddrs {
        conn, err = d.dialOnce(ctx, network, addr, ifceName, ifAddr, !isIP, log)
        if err == nil {
            return
        }
        log.Debugf("dial %s/%s via interface %s@%v failed: %s", addr, network, ifceName, ifAddr, err)
        if strict &&
            !strings.Contains(err.Error(), "no suitable address found") &&
            !strings.Contains(err.Error(), "mismatched local address type") {
            return
        }
    }
}
```

In `dialOnce()` — add `bindToDevice bool` parameter, guard `bindDevice` calls:
```go
func (d *Dialer) dialOnce(ctx context.Context, network, addr, ifceName string, ifAddr net.Addr, bindToDevice bool, log logger.Logger) (net.Conn, error) {
    // ... existing code ...
    // In both UDP and TCP branches, change:
    //   if ifceName != "" {
    // to:
    //   if ifceName != "" && bindToDevice {
}
```

#### 3. `internal/net/dialer/dialer_linux.go` — Revert loopback-specific check

Remove the loopback check added in `caa82f2` — the broader `isIP`-based fix supersedes it:

```go
func bindDevice(network, address string, fd uintptr, ifceName string) error {
    if ifceName == "" {
        return nil
    }

    host, _, _ := net.SplitHostPort(address)
    if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
        return nil
    }

    return unix.BindToDevice(int(fd), ifceName)
}
```

#### 4. `internal/net/addr_test.go` — Update `TestParseInterfaceAddr`

Update test calls to use new 4-return-value signature.

#### 5. `internal/net/dialer/dialer_linux_test.go` — Add test for loopback skip

Add a test verifying `bindDevice` is not called for IP-resolved interfaces (the loopback check is no longer in `bindDevice` itself, but the caller now skips it).

### Verification

```bash
cd x && go build ./... && go vet ./...
cd x && go test ./internal/net/... -v
cd x && go test ./internal/net/dialer/... -v
```
