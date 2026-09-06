# P2P 阶段一：mux 复用 + 内层协议矩阵验证 + 插件 token 校验

## Context

桩里程碑已验收：`OpenTunnel(peer) → 本地 endpoint → GOST 消费` 的缝隙端到端跑通，inner 仅 `tcp`（每 Dial 一隧道）。当前形态的实际缺陷：

1. **成本**：每请求一隧道 = 1 listener + 4 goroutine + 2 conn，并发 1000 即撞 fd 上限；
2. **协议覆盖**：`SupportedDialer` 白名单只有 `tcp`，tls/ws/mtcp/mtls/mws 三条前置（不二次包装、转发 Handshaker、白名单）已在 wrapper 实现，但未验证；
3. **安全**：控制通道无鉴权，仅靠 loopback 默认兜底，跨机部署前必须补 token。

本里程碑收口这三项。**不做**：rendezvous/DERP/打洞（阶段二）、x/api 覆盖、tunnel-to-destination。

## 关键事实（已实证）

- **mux 路径**：`Transport.Multiplex()` 对 `dialer.Multiplexer` 的断言（`x/chain/transport.go:92`）→ `Chain.Route` 在 mux 节点处拆分路由（`x/chain/chain.go:147-155`）。inner=mtcp 时 `Multiplex()=true`，wrapper 已委托 inner（`x/p2p/tunnel_dialer.go:106`）。
- **会话语义**：mtcp/mtls Dial 按 addr 缓存会话（`x/dialer/mtcp/dialer.go:62`），缓存命中时返回 `session.conn`、**不看 `options.Dialer`**。mux 模式下每个请求都走 `chainRoute.connect` → mux 节点 `Transport.Dial`（route-split 后 mux 节点恒为 `r.nodes[0]`，`x/chain/route.go:218`），因此 **wrapper 若先 `OpenTunnel` 再 `inner.Dial`，缓存命中时新隧道无人使用、无人关闭 —— 每请求漏一条隧道**（listener 存活至进程退出，Status 计数无界增长）。修复见改动清单 A'：惰性开洞，一条隧道 = 一个 mux 会话 = N 条流；会话死亡 → 重建（dead-session 回收已修，`session.conn.Close()` 触发 `tunnelConn.Close` → `CloseTunnel`）。
- **身份校验兼容**：mtcp Handshake 的 `session.conn != conn` 指针比对（`x/dialer/mtcp/dialer.go:120`）——wrapper 原样透传 tunnelConn，底座即会话 conn，校验自然通过。
- **TLS ServerName 无需改代码**：`x/config/parsing/node/parse.go:208` `serverName = SplitHostPort(cfg.Addr)`，p2p 下 node addr 即 peer，与非 p2p 路径语义完全一致；addr 为 IP 且证书用域名时走既有 `dialer.tls.serverName` 配置。计划旧文"届时须显式提供"过虑了，只需文档说明 + e2e 实证。
- **token 协议已在客户端侧就绪**：`x/internal/plugin/plugin.go` `WithPerRPCCredentials` 发 metadata `"token"`；`x/config` PluginConfig 已有 `token:` 字段且 `ParseP2P` 已传 `TokenOption`。**缺的只是宿主侧校验**。
- **宿主侧校验范本**：`plugin/auth/example/grpc/main.go:26-43`——`metadata.FromIncomingContext` 取 `md["token"][0]` 比对。

## 改动清单

### A'. `x/p2p/tunnel_dialer.go` — 惰性 OpenTunnel（mux 前置，必做）

现状：`tunnelDialer.Dial` 先 `OpenTunnel` 再 `inner.Dial`；mux inner（mtcp 等）缓存命中时不碰 base dialer，新开的隧道成为孤儿（fd 泄漏 + 计数无界增长）。修复：把 `OpenTunnel` 下沉进 `tunnelBaseDialer`，惰性开洞——

1. `tunnelBaseDialer.Dial` 内先 `OpenTunnel`（保留 3s `rpcTimeout` 预算在 base 内），再拨 endpoint，id 记在 base 结构上（`sync.Once`/mutex 防重复开洞）；
2. `tunnelDialer.Dial` 不再预开隧道；`inner.Dial` 返回错误时，若 base 已开洞（id 非空）则补 `CloseTunnel`，fail-closed 语义不变；
3. tcp/tls/ws 路径行为不变（base 恒拨一次）；mtcp 缓存命中时零隧道、零 RPC；
4. `Multiplex` 委托、`Handshake` 转发、`tunnelConn` 一次性关闭语义均不动。

### A. `x/p2p/tunnel_dialer.go` — 白名单扩容

`SupportedDialer` 从 `{"tcp"}` 扩到 `{"tcp","tls","ws","mtcp","mtls","mws"}`。**每项以各自 e2e 通过为准入**（逐个加，加一个验一个）。"mws" 视 mwss/wss listener 搭配可验性，可推迟。顺手修上游文案 bug：mtcp 的错误串 `"mtls: unrecognized connection"`（`x/dialer/mtcp/dialer.go:122`）改为 `"mtcp: ..."`。

### B. `x/p2p/plugin/grpc_test.go` — 测试补齐

1. `TestSupportedDialer` 更新新条目断言；
2. 新增 `TestMultiplexDelegation`：inner 用实现 `dialer.Multiplexer` 的假 dialer → 断言 `tunnelDialer.(dialer.Multiplexer).Multiplex()` 转发 inner 值、非 mux inner 返回 false（route-splitting 依赖此语义，2 个用例防回归）；
3. 新增 `TestLazyOpenTunnel`：inner 用**不调用 base dialer** 的假 dialer（模拟 mtcp 缓存命中）→ 断言 provider 的 `OpenTunnel` 未被调用；inner 调用 base dialer 时 → 断言恰好开洞一次、`inner.Dial` 失败后隧道被 `CloseTunnel`（A' 的防回归）。

既有 8 用例不动（均基于 tcp inner，语义不变）。

### C. `p2p/main.go` + `server.go` — token 校验

1. `--token` flag（默认空 = 不校验，loopback 默认不变）；比对用 `subtle.ConstantTimeCompare`（一行，顺手）；注意客户端 `RequireTransportSecurity()=false`，token 走明文 gRPC——注释里写明 control TLS 仍是硬需求；
2. `grpc.NewServer(grpc.UnaryInterceptor(authInterceptor))`：`metadata.FromIncomingContext` 取 `md["token"]`，与 `--token` 比对，不符 → `codes.Unauthenticated`。范本照抄 `plugin/auth/example/grpc/main.go`，~20 行，放 main.go；
3. 信任边界注释更新：跨机部署前提 = `--token` + control TLS（TLS 出口仍留待硬需求）。

### D. `play/` — e2e 演示配置矩阵（新文件）

| 文件 | client dialer | peer service（gost -L 等价） | 验证点 |
|---|---|---|---|
| `p2p.yaml`（既有） | tcp | `http://:18080` | 回归 |
| `p2p-tls.yaml` | tls | `http+tls://:18443` | 握手经 Handshake 转发触发 |
| `p2p-ws.yaml` | ws | `ws://:18086`（handler http） | ws 升级在隧道上 |
| `p2p-mtcp.yaml` | mtcp | `mtcp://:18090`（handler http） | **1 隧道 N 流**：多次 curl，stub 日志隧道数恒 1 |
| `p2p-mtls.yaml` | mtls | `mtcp://:18443` + service TLS | mux over TLS，含 serverName/证书匹配 |

e2e 流程同桩里程碑三终端（peer gost / p2p 宿主 / client gost + curl 本地静态服务），每个配置跑一遍。TLS 证书用 gost 自签或 play/ 既有 cert 惯例（实现时定）。

### E. 文档

1. 本计划存为 `x/docs/plans/2026-09-05-p2p-mux-token.md`（沿用日期前缀惯例）；
2. `p2p/CLAUDE.md`/`README.md`：`--token` flag 行、muxed-tunnel 从 roadmap 第 1 条移入"已实现"；
3. 桩计划文档"内层协议与 mux"节补验证结果注记。

## 已知边界（记录，不修）

- 上游竞态（Dial→Handshake 窗口 `IsClosed()` 对 `session==nil` 误判）：mux+p2p 下并发首次拨号可能多开一条隧道，身份校验失败后自动关掉（CloseTunnel 兜底），自愈，接受；
- mux 会话无进程外生命周期管理：隧道存活至进程退出（gost 既有 mux 语义同此），对中继模型反而是目标形态；
- 隧道数回归：mux 模式下"conn 关闭即计数归零"的断言不适用（会话常驻），e2e 断言改为"恒 1、进程退出后归零"。

## QUIC 演进决策点（仅记录，本里程碑不实现）

**透明性原则**：隧道只透传字节，不解释、不改写、不替代 inner 协议。协议组合（dialer↔listener 成对）由用户端到端配置决定，p2p 层永不自动替换。smux-over-QUIC-stream 是合法配置（两端照常 (mtcp↔mtcp)），性能取舍归用户。

QUIC 引擎落地时可**新增**一种 endpoint 流语义选项（每 QUIC stream 映射一次本地 accept，conn-per-dial）：选用它且配置 `tcp` 的用户获得引擎层复用；继续单管道桥接 + `mtcp` 的用户获得 smux-over-QUIC，同样合法。两种形态并存，由用户配置选择，系统不做任何自动替换。

## 验证清单

```bash
cd x && go build ./... && go vet ./... && CGO_ENABLED=1 go test -race ./p2p/...
cd p2p && go build ./... && go vet ./... && GOWORK=off go build ./...
cd gost && CGO_ENABLED=0 go build ./cmd/gost/...
# e2e 矩阵：5 配置 × 三终端 + curl；token 正/负用例（--token gost，配置带/不带 token）
# mux 成本断言：p2p-mtcp.yaml 下 10 次并发 curl，stub Status/日志隧道数恒 1；
#   单元层由 TestLazyOpenTunnel 锁定（缓存命中零 OpenTunnel、错误路径补 CloseTunnel）
```
