# Tun device 写侧探针（x 侧）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** x tun handler 在 client 模式下每 30s 往 device 写一个自回环 UDP 探针，
把发送/确认计数交给调用方（wisper 经 metadata 回调收数），读环路零改动。

**Architecture:** 新文件 `probe.go`（组包纯函数 + 探针循环，与 `keepalive` 同款
per-dial-iteration 生命周期）；`x/observer/stats` 加两个计数器（加法字段，
core 不动）；metadata 加 `probe` 开关（缺省关，gost 零行为变化）。

**Tech Stack:** Go, `golang.org/x/net/ipv4`（已在用）组包，UDP checksum 置零。

**Spec:** `wisper/docs/superpowers/specs/2026-10-07-wisper-tun-probe-design.md`
（§1/§2 是本 plan 的依据；本 plan 只覆盖 x 侧，wisper 侧见 Plan B
`wisper/docs/superpowers/plans/2026-10-07-tun-probe-watchdog.md`）

## Global Constraints

- `core/` 一行不碰（Kind 常量在 x 内定义，见 Task 1 精确值）。
- 缺省关闭：metadata 无 `probe` 键时不建 socket、不起 goroutine、不写计数
  （gost 路径零变化）。
- 本 plan 的每一步都不 `commit`／不 `push`（仓库约定 no-auto-commit）；
  每个 Task 结束时工作区只留该 Task 的文件待审。
- 发版（Task 4 的 tag+push）由 maintainer 手动做，执行人不碰。

## Review Focus

- 探针包绝不能离开本机：dst 必须是自绑 socket 的地址——Task 2 的测试 pin 死。
- IPv6-only 设备：探针禁用记 warn，不 crash——Task 2 的测试 pin 死。
- IP 头 checksum 必须正确（内核静默丢坏包）——Task 2 的测试用解析器验。
- `probeReport` 为 nil（gost/旧调用方）：调用前判空——Task 3 的测试 pin 死。
- 重拨时旧探针必须退出（per-iteration ctx），且双 writer 并发写 tun fd 是安全的
  （datagram 原子，不加锁）——Task 3 接线时保持 `keepalive` 同款模式。

---

### Task 1: metadata 开关 + 探针计数器

**Files:**
- Modify: `x/handler/tun/metadata.go`
- Modify: `x/observer/stats/stats.go`
- Test: `x/handler/tun/metadata_test.go`（若无则新建；先 `ls` 确认）、
  `x/observer/stats/stats_test.go`（追加）

**Interfaces:**
- Consumes: `mdutil.GetBool` 现有模式（`metadata.go:23,31`）。
- Produces: `metadata.probe bool`、`metadata.probeReport func(sentDelta, ackedDelta uint64)`；
  `xstats.KindProbeSent stats.Kind = 101`、`xstats.KindProbeAcked stats.Kind = 102`
  （101/102：core 用 1–5，x 内无其他自定义 Kind，测试用 999 避开）；
  `Stats.probeSent/probeAcked atomic.Uint64` + `Add`/`Get` 的 case
  （Task 2/3 用 `h.options` 之外的 `stats.Stats` 句柄传参，签名见各 Task）。

- [ ] **Step 1: 写 failing test（metadata）**

```go
func TestParseMetadataProbeDefaultOff(t *testing.T) {
    h := &tunHandler{}
    if err := h.parseMetadata(mdx.NewMetadata(map[string]any{})); err != nil {
        t.Fatal(err)
    }
    if h.md.probe {
        t.Fatal("probe defaults off")
    }
}
```

（`mdx` 是 `x/metadata` 下 metadata 构造的包名，先 grep 确认，`tun` 包内已有用法。）

- [ ] **Step 2: 运行，确认 FAIL（`h.md.probe` 未定义）**

Run: `go test ./handler/tun/ -run TestParseMetadataProbe -v`
Expected: 编译失败。

- [ ] **Step 3: 实现 `metadata` 加两个字段 + `parseMetadata` 解析**

`probe = mdutil.GetBool(md, "tun.probe", "probe")`；
`probeReport` 从 `md.Get("tun.probeReport")` 取不到则试 `md.Get("probeReport")`，
类型断言 `func(uint64, uint64)`，失败留 nil（不断言 panic）。

- [ ] **Step 4: 写 failing test（Stats 计数器）**

```go
func TestStatsProbeKinds(t *testing.T) {
    s := NewStats(false)
    s.Add(KindProbeSent, 1)
    s.Add(KindProbeAcked, 1)
    if s.Get(KindProbeSent) != 1 || s.Get(KindProbeAcked) != 1 {
        t.Fatal("probe counters not tracked")
    }
}
```

- [ ] **Step 5: 运行，确认 FAIL**

Run: `go test ./observer/stats/ -run TestStatsProbeKinds -v`
Expected: FAIL（未知 Kind 被 switch 吞掉，读回 0）。

- [ ] **Step 6: 实现 Kind 常量 + Stats 字段 + Add/Get case**

- [ ] **Step 7: 补 metadata 的 `probe:true` 解析测试 + report-func 透传测试**，
  跑全包

Run: `go test -count=1 ./handler/tun/ ./observer/stats/`
Expected: PASS。

---

### Task 2: 探针组包 + 循环

**Files:**
- Create: `x/handler/tun/probe.go`
- Test: `x/handler/tun/probe_test.go`

**Interfaces:**
- Consumes: Task 1 的 `metadata.probe`（调用方判断，本文件不管开关）。
- Produces: `probeInterval = 30 * time.Second`、`probeRecvTimeout = 5 * time.Second`、
  `probeMagic = "WSPROBE!"`（8 字节）；
  `func buildProbePacket(src net.IP, dstPort uint16, seq uint64) []byte`；
  `func runDeviceProbe(ctx context.Context, dev io.Writer, ip net.IP, report func(sentDelta, ackedDelta uint64), log logger.Logger)`。

包格式（IPv4 头 20B + UDP 头 8B + magic 8B + seq 8B = 44B）：
`src == dst == ip`（第一个 v4 spoke 地址），UDP checksum 置零（IPv4 下 0 = 无校验，
内核接受），IP 头 checksum 必须正确计算（标准 internet checksum，
全零和取反——这是唯一需要手写的算法，其他照抄 `ipv4.Header.Marshal` 或手排字节均可，
测试会验）。

循环语义：每 tick 发一次（`report(1,0)` 先记 sent，write 报错也记——acked 停滞
本身就是信号）；`SetReadDeadline(now+5s)` 等 socket 回包，magic+seq 命中记
`report(0,1)`；超时/错包不记；`ctx.Done()` 退出。socket 为
`net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})`，`ip.To4()==nil` 时直接
返回（IPv6-only 禁用，调用方记 warn——调用方是 Task 3，见下）。

- [ ] **Step 1: 写 failing test（组包纯函数）**

```go
func TestBuildProbePacket(t *testing.T) {
    src := net.ParseIP("10.10.100.250")
    pkt := buildProbePacket(src, 54321, 7)
    if len(pkt) != 44 { t.Fatalf("len=%d", len(pkt)) }
    if pkt[0] != 0x45 || pkt[9] != 17 { t.Fatal("not v4/UDP") }
    if !net.IP(pkt[12:16]).Equal(src) || !net.IP(pkt[16:20]).Equal(src) {
        t.Fatal("src/dst must both be the spoke address")
    }
    // IP 头 checksum 自验；UDP checksum 必须为零；magic+seq 位置值正确。
}
```

- [ ] **Step 2: 运行，确认 FAIL（函数未定义）**

Run: `go test ./handler/tun/ -run TestBuildProbePacket -v`
Expected: 编译失败。

- [ ] **Step 3: 实现 `buildProbePacket`**

- [ ] **Step 4: 运行，确认 PASS**

- [ ] **Step 5: 写 failing test（循环：活设备推进 sent，acked 停滞可观测）**

```go
func TestRunDeviceProbeReportsSent(t *testing.T) {
    device, kernelSide := net.Pipe() // 同 client_test.go 模式
    defer device.Close()
    defer kernelSide.Close()
    var sent, acked uint64
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go runDeviceProbe(ctx, device, net.ParseIP("10.10.100.250"),
        func(sd, ad uint64) { sent += sd; acked += ad }, xlogger.Nop())
    // kernelSide 读到第一个包：断言 44B 且 magic 命中；此时 sent>=1 且 acked==0。
}
```

（`xlogger.Nop()` 用法同 `client_test.go:67`；`runDeviceProbe` 内 socket 绑
`10.10.100.250:0` 在容器里合法——无该地址也 bind 得上？`ListenUDP` 绑非本地
IP 会报错！测试改用 `127.0.0.1` 作 spoke IP，语义等价。）

- [ ] **Step 6: 运行，确认 FAIL**

- [ ] **Step 7: 实现 `runDeviceProbe`**

- [ ] **Step 8: 补测试——写坏的设备不 panic 且 acked 永远为 0**

```go
func TestRunDeviceProbeDeadDevice(t *testing.T) {
    device, kernelSide := net.Pipe()
    kernelSide.Close() // 写端坏掉：write 报错（备用：device.Close() 后写）
    // 跑两个周期：report 的 sent 在涨，acked==0，全程无 panic。
}
```

- [ ] **Step 9: 跑全包**

Run: `go test -count=1 ./handler/tun/`
Expected: PASS（约 15s，内有既有 14s 的用例）。

---

### Task 3: 接入 handleClient

**Files:**
- Modify: `x/handler/tun/client.go`（`handleClient` 内 `go h.keepalive(...)` 旁，
  约 62 行）
- Test: 无新增集成测试（`handleClient` 需要 `Router.Dial`，既有测试只到
  `transportClient` 层，keepalive 同款无覆盖；覆盖由 Task 1 的解析测试 +
  Task 2 的循环测试承担，此处只做接线）

**Interfaces:**
- Consumes: Task 1 的 `h.md.probe`/`h.md.probeReport`，Task 2 的 `runDeviceProbe`，
  `handleClient` 已有的 `iterCtx`、`conn`（device）、`ips`。
- Produces: 无新导出（行为：`probe` 开时每轮 dial 起一个探针，`iterCtx` 结束即退）。

- [ ] **Step 1: 接线（幂等小改）**

```go
if h.md.probe {
    go h.probeDevice(iterCtx, conn, ips)
}
```

其中 `probeDevice` 为 `tunHandler` 的小方法：取 `ips` 第一个 `To4()` 非空者，
nil report 判空（gost 路径），无 v4 时 `log.Warn` 后返回；其余直调
`runDeviceProbe`。`report` 透传 `h.md.probeReport`（nil-safe：调用前判空，
判空逻辑放在 `probeDevice` 一处，`runDeviceProbe` 假定非空——测试只测
`runDeviceProbe` 非空路径 + `probeDevice` 的空 report 不起循环）。

- [ ] **Step 2: 补 `probeDevice` 的两个小测试**（nil report 不启动；
  全 v6 ips 直接返回），跑全包

Run: `go test -count=1 ./handler/tun/ ./observer/stats/`
Expected: PASS。

- [ ] **Step 3: `go vet` + `gofmt -l` 扫一遍改动文件**

---

### Task 4: 发版 x v0.23.0（maintainer 手动）

- [ ] **Step 1: 确认工作区只有本 plan 的文件**（`git status --short`）
- [ ] **Step 2: 全量构建 + 相关测试**

Run: `go build ./... && go test -count=1 ./handler/tun/ ./observer/stats/`
Expected: PASS。
- [ ] **Step 3: 打 tag 并推**（minor：新功能；patch 不够格）

```bash
git tag -a v0.23.0 -m "v0.23.0: tun device write-side probe (metadata probe, probe counters)"
git push origin v0.23.0
```

- [ ] **Step 4: 通知 Plan B 可开始**（bump 到 v0.23.0）。
