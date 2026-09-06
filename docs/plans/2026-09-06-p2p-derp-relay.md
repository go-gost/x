# P2P 阶段二：DERP 中继（官方 derper + 自写 WS-DERP 客户端子集），GOST 侧零改动

## Context

阶段一（桩 + mux + token）之后，宿主只会"loopback 听端口、桥接直拨 peer"，跨机不可达。阶段二引入 **rendezvous + 中继**，路线决策（2026-09-06 定）：

- **中继服务器 = 官方 `derper` 二进制**（`tailscale.com/cmd/derper@v1.102.3`），不集成进 GOST——x/ 零代码改动。Tailscale 公网 DERP 集群不可用（coordination 校验 tailnet node key）；自托管 derper `-verify-clients=false` 接受任意 node key。
- **客户端协议 = 自写 WS-DERP 子集**（`p2p/internal/derpclient`）。实测 import tailscale.com/derp/derphttp 客户端闭包 = 289 包（含 tailcfg/kubetypes 耦合）→ 超门槛走预订退路。传输用 **WebSocket-DERP**（标准 RFC6455 升级 + `Sec-WebSocket-Protocol: derp` + DERP 二进制帧装在 WS binary 消息），与 derper 无条件挂的 `AddWebSocketSupport` 路径互通；原生 `Upgrade: DERP` 裸帧 + FastStart 跳过 101 响应，过不了 Cloudflare 等 L7 代理，故不做。
- **peer 身份 = node key 自生成**：宿主首次启动生成 curve25519 keypair 落盘，peer-id = base64rawurl(公钥)。key 即地址；GOST 侧 `peer` 保持 opaque，配置里 node addr 直接填对方公钥。
- **不做**（阶段三）：STUN/UDP 打洞、地址发现、derper 集群 mesh。

endpoint 契约不变（[[p2p-data-plane-seam]]）：OpenTunnel → 本地 TCP endpoint → GOST 消费，隧道只透传字节。

## 关键事实（实证）

- DERP 线协议：`tailscale.com/derp@v1.102.3`（derp.go）—— Magic `"DERP🔑"`、ProtocolVersion 2、帧 = 1B type + 4B BE 长度、MaxPacketSize 64KiB、ClientInfo = 32B pub + NaCl box（`NodePrivate.SealTo(serverPub, json)` 布局 = 24B nonce + box）。未知帧静默跳过（参考客户端 recv switch 无 default）。
- derper 启动需 `-c <json>` 配置（`{"PrivateKey":"privkey:<hex>"}`，首次运行自动生成）；`-certmode manual -certdir` 用 `<hostname>.crt/.key`；`-a :4433` 配 `-certmode manual` = HTTPS。
- derper 是纯中继不加密负载：保密性 = 内层 dialer（mtls/tls/wss），与 p2p 透明性原则一致。Cloudflare 橙云部署：WS-DERP 天然兼容，客户端 keepalive 30s ≤ CF ~100s 空闲超时；大流量有 ToS 风险（分级用法：直连主用、CF 当被墙兜底）。

## 改动清单（全部在 `p2p/` 模块）

### T1. `p2p/internal/derpclient/` — WS-DERP 子集客户端（新包）

`client.go`：`Generate`/`PrivateKey`/`PublicKey`（curve25519 + `SealTo`/`OpenFrom` 复刻 types/key 布局）；`Dial(ctx, url, priv, tlsCfg)` = coder/websocket 标准 WS 升级（subprotocol "derp"、压缩禁用）→ DERP 握手（FrameServerKey magic 校验 → FrameClientInfo box 自证 → FrameServerInfo box 开解）→ `SendPacket`/`Recv`/`KeepAlive`/`Close`。Client 持有独立生命周期 context（NetConn 不能复用 Dial ctx，否则 Dial 返回后 cancel 立即掐断读循环——第一个实测坑）。依赖：`golang.org/x/crypto` + `github.com/coder/websocket`（零依赖，官方 WS 路径同款，互操作锚点）。Escape hatch 写进注释（退到 import tailscale 客户端）。

### T2. `p2p/engine.go` + `server.go`/`main.go` 接线

- `engine.go`：`Engine` 对称双角色——1 个 DERP 长连接 + 收包 pump（按 srcKey 路由到 per-peer 适配器）+ keepalive(30s) + 断线重连 ticker(5s)；per-peer 适配器 = smux 会话（`net.Conn`，Write=SendPacket、Read=入站队列）；**会话角色由公钥序决定**（两端确定性收敛一个 smux 会话），smux 双向都能开流；入站 accept 循环 → 桥接 `--target`（half-close 语义沿用桩）。pump 对未知 src 也建会话（入站隧道不被漏）。
- `server.go`：`OpenTunnel` 在 derp 模式校验 peer 为 32B key、`bridge()` 把"拨 peer host:port"换成 `engine.OpenStream(peer)`；桩模式路径原样。
- `main.go`：`--derp <url>`（模式开关）、`--key <file>`（hex 私钥，缺则 0600 生成，启动打印 base64 公钥）、`--target`（入站桥接目标）；启动即 `engine.Connect()` 注册到中继（rendezvous 节点必须常连），失败则后台重连并继续服务 gRPC。

### T3. e2e（单机三进程模拟跨机中继，见验证）

新增 `play/p2p-derp.yaml`（tcp inner）、`play/p2p-derp-mtcp.yaml`（mtcp inner）。

### T4. 文档（本文件 + p2p/README.md + p2p/CLAUDE.md）

## 已知边界（记录，不修）

- derper 无鉴权 = 公共中继：知道 pubK_b 的任何人都能向 B 发包；负载由内层协议保护；入站 target 是宿主自己的 `--target` 配置，不由对端指定——无 SSRF。
- 客户端不能请求断开某 peer（ClosePeer 是 mesh 特权帧）：会话清理靠 smux keepalive + 本地拆适配器。
- 单收包 pump（每宿主一 goroutine）：千级隧道够用，瓶颈时再分片（ponytail 边界）。
- smux 流无半关（CloseWrite）：桥接走全关降级分支，HTTP 实测可用。
- DERP 引擎与桩模式互斥（`--derp` 开关），无运行时切换/热重载。

## 验证（全绿，2026-09-06）

```bash
cd p2p && go build ./... && go vet ./... && GOWORK=off go build ./...
cd p2p && CGO_ENABLED=1 go test -race ./...            # 8/8（derpclient 6 + engine 1 + parsePeerKey 1）
# derper 互操作：go install tailscale.com/cmd/derper@v1.102.3 + 自签 cert
# e2e：derp-tcp PASS / derp-mtcp PASS / derp-neg PASS（不可达 peer 拒绝）
# 回归：桩模式 7 用例（tcp/tls/ws/mtcp/mtls/token±）全 PASS
cd x && go build ./... && go vet ./...                 # x/ 零 diff
```

验收标准达成：单机三进程 e2e 全过、与官方 derper 互通、x/ 模块零改动（仅文档 + play 配置）。
