# Issue #777: relay+quic "假死" (Hanging) Under High Load

**Issue**: https://github.com/go-gost/gost/issues/777
**Status**: Open, labeled `NeedsInvestigation`
**Reported**: 2025-09-05
**Maintainer note**: "May related to connection multiplexing or reuse" (@fernvenue)

## 适用版本 / Version Context

本分析最初基于 issue 报告版本 **v3.2.4**（docker）。当前 `main` 已被以下提交修复部分根因，**下列 PRIMARY/SECONDARY/TERTIARY 在 v3.2.4 成立，但在当前 `main` 已不成立**：

- `5484717` (2026-06-20) — 新增 `quicSession.IsClosed()`，并在 `Dial()` 复用前检查 / 驱逐死亡 session（修复 "僵尸 session"）。
- `9fab332` (2026-06-21) — `OpenStreamSync` 加 `30s` 超时；在 `GetConn()` 之前释放 `sessionMutex`（修复全局 mutex 阻塞）。

Plan 文档 `777-quic-hanging-plan.md` 为最新修正版（含剩余真问题与修复方案）。

## Symptom

Config: `gost -L socks5://:10086 -F relay+quic://IP:PORT?keepalive=true&ttl=21s&auth=XXXX`

Under high request frequency, connections are accepted (handler logs visible) but no forwarding occurs (no forwarding logs). Restarting the Docker container immediately recovers.

## Root Cause Analysis

### 已在当前 main 修复（v3.2.4 中存在）

#### ~~PRIMARY: Global `sessionMutex` 在 `OpenStreamSync` 期间被持有~~ — 已修复

原诊断认为 `quicDialer.Dial()` 在整个方法期间持有 `sync.Mutex`，包括会阻塞的 `OpenStreamSync`，导致全局假死。当前代码已在 `GetConn()` 之前释放锁：

```go
// x/dialer/quic/dialer.go
d.sessionMutex.Unlock()              // :99 在 GetConn 之前释放
conn, err = session.GetConn(ctx)     // :101 锁外执行 OpenStreamSync
```

`OpenStreamSync` 不再阻塞全局 mutex，但单个连接在死 session 上仍可能阻塞至超时（见 P1）。

#### ~~SECONDARY: `OpenStreamSync(context.Background())` 无超时~~ — 已修复

当前代码使用 `context.WithTimeout(ctx, 30*time.Second)`，不再是 `context.Background()` 无限阻塞。原诊断假设已不成立（提交 `9fab332`）。

#### ~~TERTIARY: 无 session 健康检查 / 驱逐~~ — 已修复

当前 `Dial()` 复用前调用 `session.IsClosed()` 检查并驱逐死亡 session：

```go
// x/dialer/quic/dialer.go
session, ok := d.sessions[addr]
if session != nil && session.IsClosed() {
    delete(d.sessions, addr) // session is dead
    ok = false
}
```

`IsClosed()` 观察 `session.session.Context().Done()` channel 判定 session 是否存活（提交 `5484717`）。

### 仍真实存在的问题（P1–P3）

#### P1 (HIGH): 请求 ctx 未透传到 `GetConn` / `OpenStreamSync`

`Router` 默认 **15s 超时**（`x/chain/router.go:36`），并包裹为 `context.WithTimeout(ctx, 15s)` 透传至 `quicDialer.Dial`（`x/chain/router.go:108` → `route.Dial` → `transport.Dial` → `dialer.go:50`）。但 `GetConn()` 收到的仍是 `context.WithTimeout(context.Background(), 30s)`（由 `Dial` 内部构造），请求 ctx 被丢弃：

- `OpenStreamSync` 不遵守上游 15s 截止时间；
- 请求被取消时，`OpenStreamSync` 不会随之取消。

一个卡死的 QUIC session 仍会让每个新连接在 `OpenStreamSync` 上阻塞最多 30s（单连接级 hang，可被上游 ctx 取消则是修复后的行为）。

#### P2 (MEDIUM): keepalive 在 dialer / listener 间不对称

- Dialer (`x/dialer/quic/metadata.go:35`)：`md == nil || !md.IsExists(keepAlive) || GetBool(keepAlive)` → **默认开启**（周期 10s）。
- Listener (`x/listener/quic/metadata.go:47`)：`if GetBool(keepAlive)` → **仅显式 `keepalive=true` 才开启**。

若用户只在 client (`-F`) 配 `keepalive=true`，server 端 QUIC listener 不发 PING。过 NAT 时服务端回程映射过期，而客户端以为连接仍存活 —— 与 issue 症状吻合。

#### P3 (LOW): 两端均未显式设置 `MaxIdleTimeout` 默认

dialer 与 listener 均解析 `maxIdleTimeout` 并传入 `quic.Config.MaxIdleTimeout`，默认值为 `0` → quic-go 自身默认（约 30s），无显式下限。设置对称、合理的显式默认（90s）可让死 session 被 quic-go 自身更快检测，与 P2 互补。

## Recommended Fixes

| 编号 | 问题 | 状态 | 方案 |
|------|------|------|------|
| ~~PRIMARY~~ | 全局 mutex 持有 | **已修复** `9fab332` | — |
| ~~SECONDARY~~ | 无超时 OpenStreamSync | **已修复** `9fab332` | — |
| ~~TERTIARY~~ | 无 IsClosed 检查 | **已修复** `5484717` | — |
| Fix B | P1 ctx 未透传 | 待实施 | `GetConn(ctx)` 透传 + 30s 上限，镜像 icmp |
| Fix C | P2 keepalive 不对称 | 待实施 | listener 默认开启 keepalive |
| Fix D | P3 MaxIdleTimeout 默认 | 待实施 | 两端默认 90s，允许 `maxIdleTimeout=` 覆盖 |

详见 `777-quic-hanging-plan.md`。

## Key Files

| File | Role |
|------|------|
| `dialer/quic/dialer.go` | QUIC dialer；窄锁（GetConn 移出锁）；IsClosed 复用前检查 |
| `dialer/quic/conn.go` | `GetConn(ctx)` / `IsClosed()` — OpenStreamSync 带 30s 超时 |
| `dialer/quic/metadata.go` | keepalive 默认 ON；maxIdleTimeout 解析 |
| `listener/quic/listener.go` | QUIC listener，keepAlivePeriod 传入 quic.Config |
| `listener/quic/metadata.go` | Listener keepalive / maxIdleTimeout 解析 |
| `dialer/icmp/dialer.go` | ICMP dialer — 与 quic 结构一致，改动需镜像 |
| `dialer/icmp/conn.go` | ICMP `quicSession` / `GetConn(ctx)` |
| `connector/relay/connector.go` | Relay connector（无状态，每调用一次） |
| `chain/router.go` | Router 默认 15s 超时，构造超时 ctx |
| `chain/route.go` | `route.Dial()` → `Transport.Dial()` |
