# go-gost/gost#842: Per-App Transparent Proxy via cgroup + nftables + Policy Routing

## Context

Issue [#842](https://github.com/go-gost/gost/issues/842) requests per-application transparent proxying. Instead of the originally proposed `gost run` subcommand with namespace isolation, this plan enhances the existing `tungo` listener with cgroup-based traffic filtering — achieving the same goal with **far less code** (estimated ~180 lines vs. ~460+ lines for namespace approach) and **zero changes to the handler layer**.

## Core Insight

The `tungo` handler already handles all packets that arrive on the TUN device through gVisor netstack → GOST chain forwarding. The problem is not *how to process packets* — it's *how to get only the target process's packets onto the TUN*. The answer: **OS-level traffic marking + policy routing**.

```
所有进程 (除目标进程外的所有流量) ──→ main routing table ──→ eth0 ──→ 正常上网

目标进程 (在 cgroup /gost-tunnel 中)
  └─→ nftables OUTPUT: socket cgroupv2 → meta mark set <mark>
       └─→ ip rule fwmark <mark> → table <n>
            └─→ default dev <tun> → TUN 设备 → tungo handler → 代理链
```

The `tungo` handler receives only the marked traffic. Zero changes to handler, gVisor, or chain code.

## Mechanism: nftables `socket cgroupv2` Match

Kernel 5.x+ and nftables support matching on the **cgroup v2 path** of the sending socket:

```bash
nft add rule inet gost output socket cgroupv2 level 2 "gost-tunnel" meta mark set 0x1
```

This marks every packet originating from processes in the cgroup `/sys/fs/cgroup/gost-tunnel`. The mark is then used by policy routing to divert those packets to the TUN device instead of the default route.

**Why this works:**
- Socket-level, not per-packet — applies to all packets from matching processes
- Works for TCP and UDP (OUTPUT chain)
- Child processes automatically inherit cgroup membership
- No LD_PRELOAD, no namespaces, no forked child processes
- The target process has zero knowledge it's being proxied (true transparent proxy)

## Design: Enhance `tungo` Listener

### New metadata fields

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cgroup` / `tun.cgroup` | string | `""` (disabled) | cgroup v2 path relative to `/sys/fs/cgroup/` (e.g. `"gost-tunnel"`) |
| `cgroup.create` / `tun.cgroup.create` | bool | `false` | Auto-create the cgroup directory if it doesn't exist |
| `cgroup.cleanup` / `tun.cgroup.cleanup` | bool | `false` | Remove cgroup + nftables rules + ip rules on listener Close() |

When `cgroup` is empty (default), behavior is **completely unchanged** — no nftables rules, no policy routing.

### Modified files

#### 1. `x/listener/tungo/metadata.go` — parse new fields (~20 lines)

```go
type metadata struct {
    config  *tun_util.Config
    guid    string
    cgroup struct {
        path    string   // e.g. "gost-tunnel"
        create  bool     // auto-create cgroup dir
        cleanup bool     // remove rules on close
    }
}
```

Parse `cgroup`, `cgroup.create`, `cgroup.cleanup` from metadata.

#### 2. `x/listener/tungo/tun_linux.go` — add `setupCgroupFilter()` (~120 lines)

New function called from `createTun()` after TUN is up:

```go
func (l *tunListener) setupCgroupFilter() error {
    if l.md.cgroup.path == "" {
        return nil  // feature not enabled
    }

    // 1. Verify cgroup exists or create it
    cgroupPath := filepath.Join("/sys/fs/cgroup", l.md.cgroup.path)
    if l.md.cgroup.create {
        os.MkdirAll(cgroupPath, 0755)
    }
    if _, err := os.Stat(cgroupPath); err != nil {
        return fmt.Errorf("cgroup %s does not exist: %v", cgroupPath, err)
    }

    // 2. Generate a unique table name and mark value
    tableName := fmt.Sprintf("gost-%s", l.md.config.Name)
    fwmark := l.md.cgroup.mark
    if fwmark == 0 {
        fwmark = 0x1  // default mark
    }
    tableID := l.md.cgroup.table
    if tableID == 0 {
        tableID = 100  // default routing table
    }

    // 3. Add nftables rule:
    //    nft add table inet <tableName>
    //    nft add chain inet <tableName> output "{ type filter hook output priority 0; }"
    //    nft add rule inet <tableName> output socket cgroupv2 level 2 "<path>" meta mark set <fwmark>
    for _, cmd := range [][]string{
        {"nft", "add", "table", "inet", tableName},
        {"nft", "add", "chain", "inet", tableName, "output",
            "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"},
        {"nft", "add", "rule", "inet", tableName, "output",
            "socket", "cgroupv2", "level", "2",
            strconv.Quote(l.md.cgroup.path),
            "meta", "mark", "set", strconv.FormatUint(uint64(fwmark), 10)},
    } {
        if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
            return fmt.Errorf("nftables setup: %v", err)
        }
    }

    // 4. Add policy routing:
    //    ip rule add fwmark <fwmark> table <tableID>
    rule := netlink.NewRule()
    rule.Mark = int(fwmark)
    rule.Table = tableID
    if err := netlink.RuleAdd(rule); err != nil && !os.IsExist(err) {
        return fmt.Errorf("ip rule add fwmark %d table %d: %v", fwmark, tableID, err)
    }

    // 5. Add default route in the table pointing to TUN:
    //    ip route add default dev <tun-name> table <tableID>
    // (this is already handled by existing addRoutes() — just add route to the table)

    // 6. Store for cleanup
    l.md.cgroup.tableName = tableName
    l.md.cgroup.fwmark = fwmark
    l.md.cgroup.tableID = tableID

    return nil
}
```

#### 3. `x/listener/tungo/listener.go` — cleanup in Close() (~30 lines)

```go
func (l *tunListener) Close() error {
    // ... existing close logic ...

    // Cleanup nftables rules and policy routing
    if l.md.cgroup.cleanup && l.md.cgroup.tableName != "" {
        exec.Command("nft", "delete", "table", "inet", l.md.cgroup.tableName).Run()
        rule := netlink.NewRule()
        rule.Mark = int(l.md.cgroup.fwmark)
        rule.Table = l.md.cgroup.tableID
        netlink.RuleDel(rule)
    }
    return nil
}
```

#### 4. `x/config/parsing/parse.go` — new metadata key constants (~6 lines)

```go
const (
    // MDKeyCgroup sets the cgroup v2 path for per-process traffic filtering
    // on TUN/TAP/TUNGO listeners.
    MDKeyCgroup = "cgroup"

    // MDKeyCgroupCreate auto-creates the cgroup directory.
    MDKeyCgroupCreate = "cgroup.create"

    // MDKeyCgroupCleanup removes nftables rules and policy routing on listener close.
    MDKeyCgroupCleanup = "cgroup.cleanup"

    // MDKeyCgroupMark sets the fwmark value used for cgroup traffic (default 0x1).
    MDKeyCgroupMark = "cgroup.mark"
)
```

### New dependency

`netlink.RuleAdd` / `netlink.RuleDel` from `github.com/vishvananda/netlink` — **already vendored** at `v1.1.1-0.20211118161826-650dca95af54`. No new Go dependency needed.

`nft` command — **already included** in Dockerfile (line 31: `apk add nftables`). No new system dependency needed.

## Usage

### YAML config

```yaml
services:
- name: per-app-proxy
  addr: :0
  handler:
    type: tungo
    chain: chain-0
  listener:
    type: tungo
    metadata:
      net: 10.0.0.1/24
      mtu: 1420
      cgroup: gost-tunnel           # cgroup path (relative to /sys/fs/cgroup/)
      cgroup.create: true           # auto-create the cgroup
      cgroup.cleanup: true          # remove rules on exit
      cgroup.mark: 0x1              # fwmark value (optional, default 0x1)

chains:
- name: chain-0
  hops:
  - nodes:
    - addr: socks5://proxy:1080
      connector:
        type: socks5
      dialer:
        type: tcp
```

Then:
```bash
# Start GOST
sudo gost -C gost-run.yaml

# In another terminal, start target process in the cgroup
sudo cgexec -g cpu,memory,pids:gost-tunnel firefox
# OR on cgroup v2 systems:
echo $$ > /sys/fs/cgroup/gost-tunnel/cgroup.procs  # current shell
firefox  # all its traffic goes through TUN → proxy chain
```

### Inline CLI (via existing -L flag)

```bash
gost -L "tungo://:0?net=10.0.0.1/24&cgroup=gost-tunnel&cgroup.create=true&cgroup.cleanup=true" \
     -F "socks5://proxy:1080"
```

### preUp/postDown alternative (zero code, already works)

GOST already supports `preUp`/`postDown` hooks that run shell commands. Users can achieve the same result today:

```yaml
services:
- name: per-app-proxy
  addr: :0
  handler:
    type: tungo
    chain: chain-0
  listener:
    type: tungo
    metadata:
      net: 10.0.0.1/24
      preUp: |
        nft add table inet gost-tun
        nft add chain inet gost-tun output '{ type filter hook output priority 0; }'
        nft add rule inet gost-tun output socket cgroupv2 level 2 "gost-tunnel" meta mark set 0x1
        ip rule add fwmark 0x1 table 100
        ip route add default dev tungo table 100
      postDown: |
        nft delete table inet gost-tun
        ip rule del fwmark 0x1 table 100
        ip route del default table 100
```

This already works with **zero code changes**. The code change proposed above simply makes it a first-class configuration option instead of requiring shell commands.

## Verification

### Unit-level verification
- `go build ./...` — entire workspace
- `go vet ./...` — x/ module
- Verify `nftables` command is available in test environment
- Verify `netlink.RuleAdd` works (already tested by existing `netlink.RouteReplace` usage)

### Integration test (manual)
```bash
# Start echo server on host
python3 -m http.server 8080 &

# Start GOST
sudo ./gost -C test-cgroup.yaml

# Put test process in cgroup and make a request
sudo cgexec -g cpu,memory:gost-tunnel curl http://example.com
# Verify traffic goes through proxy chain, not directly
```

### Existing tests unaffected
- No handler changes → all existing tungo handler tests pass
- No listener code path changes when `cgroup` is empty → all existing listener tests pass

## Summary

| Metric | Value |
|--------|-------|
| New code | ~180 lines |
| Modified files | 4 |
| New files | 0 |
| New dependencies | 0 (netlink already vendored, nftables already in Docker) |
| Handler changes | **0** |
| gVisor changes | **0** |
| Chain/Router changes | **0** |
| Service model changes | **0** |
| CLI conflict with `--` | **None** |
| Privilege required | CAP_NET_ADMIN (existing TUN requirement) + rw access to cgroup dir |
| Kernel requirement | 5.x+ (cgroup v2 + nftables `socket cgroupv2` match) |
| Child process tracking | Automatic (cgroup containment) |
| TCP support | Yes |
| UDP support | Yes (OUTPUT path; UDP replies match via conntrack) |
| Cleanup on exit | Configurable (`.cleanup=true`) |
