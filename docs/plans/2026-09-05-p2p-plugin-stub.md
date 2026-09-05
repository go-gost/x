# P2P 插件缝隙跑通桩（Stub Milestone）实现计划

## Context

**背景**：研究 tailcat/Tailscale 后，GOST 确认要做 "P2P-as-连接建立方式"，架构结论为：
- 不 import tailscale.com（依赖闭包实证：连最底层 derp 都拖 31+ 个包）；
- 未来 P2P traversal 引擎（rendezvous/中继/打洞/保活）**外置为插件进程**，DERP-subset 中继 server 留作 GOST 进程内 service（后续里程碑）；
- 插件契约：control 走 gRPC unary，data 面走"插件返回本地 TCP endpoint、GOST 本地拨号"。

**本里程碑（用户选定）**：只做**插件缝隙 + 桩实现**的端到端跑通——证明"经插件建隧道→本地端点→GOST 消费"这条缝隙与生命周期是对的。**不做** NAT 穿透/DERP/加密/rendezvous。

**交付形态（架构修订，用户拍板）**：p2p 插件为**常规命名插件组件**（与 recorder/bypass 同构：顶层 `p2ps:` 配置段 + `registry.P2PRegistry()` + loader 注册），**不新增 dialer**。任何现有 dialer 通过**单条节点 metadata `p2p: <name>`** 声明"基础通路走哪个 p2p 插件"；**在节点解析处把 dialer 包一层 p2p 适配器**（x 本地实现 core `dialer.Dialer`，无 core 改动），把内层 dialer 的 `options.Dialer` 底座替换为"向插件 OpenTunnel(peer)→拨本地端点"，dialer 自身协议（tls/ws/mtls/mws）原样跑在隧道之上——**协议零耦合（dialer 名即协议；内层握手照搬内层自身 `Handshaker`，wrapper 仅负责转发触发，见"内层协议与 mux"），无 `p2p.inner`，无新增 dialer**。**p2p 宿主独立成 repo**（同 llm-api-converter 形态：workspace 根独立目录 p2p/ + 自有 go.mod/.git + 加入 go.work），**不进 gost-plugins**——p2p 引擎（DERP/打洞）复杂度归宿主 repo，gost-plugins 零改动。GOST 侧零 core 改动，connector 复用现有 http/socks5。

## 一、随依赖顺序新建/修改的文件

### A. `plugin/` 模块 — control 协议（先做，其余模块依赖它）

| 文件 | 内容 | 镜像 |
|---|---|---|
| `plugin/p2p/proto/p2p.proto`（新） | P2P service：OpenTunnel/CloseTunnel/Status | `plugin/sd/proto/sd.proto` |
| `plugin/p2p/proto/p2p.pb.go` / `p2p_grpc.pb.go`（新，生成物入库） | protoc 生成 | 同目录既有生成物 |

生成命令（从 `plugin/p2p/proto/` 目录执行）：
```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative p2p.proto
```
工具链已实证可用（protoc 3.15.8 / gen-go 1.28.1 / gen-go-grpc 1.2.0，均与 plugin/CLAUDE.md 记录一致）。`go_package` 必须设为 `github.com/go-gost/plugin/p2p/proto`（**不要**重蹈 recorder 的 go_package 指向 ingress 的坑）。不在 plugin/ 加 example/（`p2p/` 宿主 repo 即参考实现，偏离 plugin/CLAUDE.md 的 example 惯例是有意为之），不加 HTTP 变体（YAGNI）。

**Proto 契约**（最小可扩展，proto3 字段后加兼容）：
```proto
syntax = "proto3";
package proto;
option go_package = "github.com/go-gost/plugin/p2p/proto";

// peer 对客户端不透明，具体语义由插件自身决定（可为 rendezvous 能力标识、WG 公钥、
// 自定义凭据）。客户端仅透传。
message OpenTunnelRequest { string peer = 1; }
// id 由服务端分配，客户端关闭时原样回传。
message OpenTunnelReply {
  bool ok = 1;
  string id = 2;
  string endpoint = 3; // 隧道句柄（GOST 不解释）：v1 为本地可拨 TCP "host:port"（不带 scheme），未来可承载流凭证
  string error = 4;    // ok==false 时的人类可读原因
}
message CloseTunnelRequest { string id = 1; }
message CloseTunnelReply { bool ok = 1; }
message StatusRequest {}
message StatusReply { int32 tunnels = 1; } // 未来路径/状态信息在此加字段

service P2P {
  rpc OpenTunnel(OpenTunnelRequest) returns (OpenTunnelReply);
  rpc CloseTunnel(CloseTunnelRequest) returns (CloseTunnelReply);
  rpc Status(StatusRequest) returns (StatusReply);
}
```
错误语义（单一失败通道，消除双通道歧义）：OpenTunnel 校验/传输失败 → 只回 `status.Error(codes.InvalidArgument/Unavailable)`（不回包体）；业务失败（如 listen 失败）→ 包体 `ok:false` + error 串且 gRPC status 为 OK；客户端对二者任一即判失败。CloseTunnel 对未知 id 返回 `ok:true`（契约幂等）。

### 扩展性契约（通用性——接口对超越 DERP 的实现保持通用）

契约域 = **"TCP 语义的局部字节管道"**——契约卡在这个最大公约数上:"**给对端能力标识,产出一条局部字节管道**"。经 TCP 语义表达的引擎(DERP 会合+中继、WG 直连、HTTP/WS 隧道)在契约域内。**UDP 数据报类引擎(打洞产物)不在 v1 契约域内**:丢包且无拥塞控制的信道上跑裸 TCP 不成立,需要完整可靠流层(QUIC/kcp 级复杂度)——届时按不变式 3 新增 RPC 家族或扩展 endpoint 语义,是**显式未来对撞点**,不是已解决的问题。三条不变式,实现时不得破坏:

1. **`peer` 以插件为界不透明**——实现细节只在插件内解析/分发。注意客户管线在 peer 到达 dialer 前先过 `xnet.Resolve(node.Addr)`（`x/chain/route.go:233`，受节点 resolver/hostmapper 影响）；桩下 resolver 为空、host:port 直通，将来 peer 若是非 host:port 的 rendezvous 标识需在此绕开。插件内部可以按 peer 前缀分发到多个后端实现。
2. **`endpoint` 是唯一输出（== 隧道句柄/凭证）**——对 GOST 完全透明。v1 具体化为本机可拨号的 TCP `host:port`；它是逻辑会话标识而非深层语义。承载 gRPC 双向流凭证是部署维度出口②的前提改造，不是本契约的自动演进（见"部署维度"出口②）。GOST 侧永远只消费普通 `net.Conn`。
3. **只靠 proto3 增量演进，不手写新契约**——加字段=向后兼容；未来数据报/QUIC 隧道=在该 service 下新增 unary RPC 家族（老实现对未知 RPC 返回 Unimplemented，不 break）。**本桩不加能力协商 RPC、不加 `network` 字段**——additive-safe 的东西需要时再加（YAGNI）。

### 内层协议与 mux（协议归 dialer 名，p2p 只供隧道底座；wrapper 需转发 Handshaker）

p2p 不定义自己的协议层——**对端协议由 dialer 名字承担**，p2p 适配器只把内层 dialer 的底座 conn（`options.Dialer`）替换为"向插件 OpenTunnel(peer)→拨本地端点"。

**评审更正（原来写"零新握手代码"，实证不成立）**：内层 tls/ws/mtls/mws/mtcp **全部实现 `dialer.Handshaker`**，且 tls/ws 的 `Dial` 只返回**裸底座 conn**——TLS 握手 / ws 升级整个在各自的 `Handshake` 方法里（`x/dialer/tls/dialer.go:44`、`x/dialer/ws/dialer.go:78`）。`Transport.Handshake` 靠 `tr.dialer.(dialer.Handshaker)` 类型断言触发内层握手（`x/chain/transport.go:59`）——wrapper 夹在 Transport 与内层之间，**不转发 Handshaker，inner=tls/ws 拿到的就是明文裸 conn（静默失败）**。所以不是"零新握手代码"，而是"握手代码照搬内层自身 Handshake，wrapper 负责让它在 `Transport.Handshake` 处被触发"。三条前置：

1. **tunnelConn 在"合成底座"层创建**：`tunnelDialer.Dial` 对 inner 的返回值**原样透传、不二次包装**——否则 mtcp/mtls 的 `session.conn != conn` 连接身份校验（`x/dialer/mtcp/dialer.go:116`）按指针比对必炸；
2. **实现 `dialer.Handshaker` 并转发 inner**（连同 `AddrHandshakeOption` 原样传）；
3. **内层 dialer 白名单（fail-closed）**——wrapper 的隐含前提是"内层经 `options.Dialer` 拨一条纯 TCP 流并当底座用"，并非所有 dialer 满足：kcp/udp/quic 系底座是数据报 conn；http2/h2c 的 `Dial` 有 probe-dial-then-close（`x/dialer/http2/dialer.go:75-86`），会开一条隧道立刻销毁。接线处以白名单校验 `dialCfg.Type`（`SupportedDialer`，定义在 `x/p2p/tunnel_dialer.go`），不在列 → `ParseNode` 报错。本里程碑白名单仅 `tcp`（实测过）；tls/ws 完成三终端验证后各加一行。新 dialer 默认不可用（fail-closed）是注入底座场景的正确默认。

```
tunnelDialer.Dial(ctx, peer, opts...):   // opts 来自 Transport.Dial（含 HostDialOption / NetDialerDialOption(netd)）
  id, endpoint := pr.OpenTunnel(ctx, peer)                // 限时 ctx（同 CloseTunnel）
  base := 合成拨号器(恒返 &tunnelConn{endpoint, pr, id, once})  // 无视 network/addr；隧道 conn 在此层创建
  conn := inner.Dial(ctx, peer, append(opts, NetDialerDialOption(base))...)  // 末尾追加覆盖底座
  return conn                                             // 原样透传：底座即 tunnelConn，不二次包装

tunnelDialer.Handshake(ctx, conn, opts...) =  // 实现 dialer.Handshaker（前置 2）
  inner.(dialer.Handshaker).Handshake(ctx, conn, opts...)  // 内层无 Handshake（tcp）→ 原样返回 conn
```
`inner=tcp`（桩默认）：无握手、无身份校验，1:1 退化——**本里程碑唯一验证的 inner**。`inner=tls/ws`：桩是透明 TCP 转发，补齐三条前置即可用（peer 侧需对应 tls/ws listener 且 ServerName 匹配），留待后续验证。`inner=mtls/mws/mtcp`：额外受 mux 会话生命周期约束（见下），归未来里程碑。**无 `p2p.inner`，无新 dialer，无 ALPN 协商。**

mux 细节：会话缓存/复用资产生命周期归 **内层 mux dialer**（mtcp/mtls 自带 per-addr 会话缓存，`x/dialer/mtcp/dialer.go:62-95`；wrapper 只供底座）。隧道即会话的底座 conn（== tunnelConn）：会话关闭→底座 Close→幂等 CloseTunnel；会话死亡→下次 Dial 经 `session.IsClosed()` 判定重建（`x/dialer/mtcp/dialer.go:63`）。插件/proto 无感。未来注意点：① 内层 TLS 的 ServerName 默认取节点 addr（`x/config/parsing/node/parse.go:207`，即 SplitHostPort(cfg.Addr)），届时须显式提供；② 隧道生命周期跟 mux 会话（上）；③ 对端约束（部署选择非代码）：mux 模式隧道落对端 `mtcp`/`mtls`/`mws` listener（`mux.ServerSession`，`x/listener/mtcp/listener.go:142`），普通模式落 http/socks/relay listener。**dead-session 回收（已落地，独立于 p2p 的既有 fd 泄漏修复）**：`x/dialer/{mtcp,mws,mtls}` 的 `Dial` 删除 dead session 前须 `session.Close()` + `session.conn.Close()`，否则底座 conn 及其 p2p 隧道永久泄漏（build/vet 已过）。已知上游竞态（记录，不修）：`muxSession.IsClosed()` 对 `session.session==nil` 返回 true（`x/dialer/mtcp/conn.go:33-35`），Dial→Handshake 窗口内并发 Dial 会误判 dead 而重建。

**否掉插件侧复用**（proto 加 `OpenStream(tunnelID)` 让插件多路复用）：等于在插件内再造 smux/yamux，绕开 GOST 自带帧复用，不采用。

### B. 新独立 repo `p2p/` — 桩宿主（不进 gost-plugins）

| 文件 | 内容 | 镜像 |
|---|---|---|
| `p2p/go.mod`（新） | `module p2p`（同 llm-api-converter 纯模块名风格）；require `github.com/go-gost/plugin`、`google.golang.org/grpc` | `llm-api-converter/go.mod` |
| `p2p/main.go`（新） | `package main`：flag `--addr`（默认 `127.0.0.1:8003`，gRPC 监听——loopback 默认是安全边界，见桩语义尾注）、`--bind`（默认 `127.0.0.1`，数据面监听地址，见"部署维度"）、`net.Listen`、`grpc.NewServer`、`proto.RegisterP2PServer`、`s.Serve(ln)`；slog 配置 | `gost-plugins/limiter/traffic/limiter.go` 的 ListenAndServe 形状（**去 cobra**——单服务 repo 无需） |
| `p2p/server.go`（新） | `server`：嵌 `UnimplementedP2PServer`、`mu`、`tunnels map[string]*tunnel`；OpenTunnel/CloseTunnel/Status（语义见下）；`git init` | 同上 |
| `gost-plugins/` | **零改动**（干净性目标：p2p 复杂度不落地此处） | — |
| `go.work`（改） | 追加 `./p2p`（同既有 `./llm-api-converter` 条目） | — |

桩语义（OpenTunnel）：
1. `net.SplitHostPort(req.Peer)` 校验，失败 → `codes.InvalidArgument`；
2. `net.Listen("tcp", bind+":0")`（bind 默认 `127.0.0.1`，可配可达接口）；`id := fmt.Sprintf("tunnel-%d", atomic.AddInt64(&seq, 1))`（自增计数，免 uuid 依赖）；
3. 注册 `tunnel{id, ln, conns map[net.Conn]struct{}, target}`，起 accept 循环：每接受一个连接 → `net.DialTimeout("tcp", target, 5s)` → 双向 `io.Copy`（每方向一 goroutine），任一侧结束 → **对端 `net.TCPConn.CloseWrite()`**（半关闭转发），两侧都结束后才双向 `Close`——避免"一端 EOF 即双向关闭"截断仍想读的另一端；
4. 回复 `{Ok:true, Id:id, Endpoint: ln.Addr().String()}`。
CloseTunnel：删 map 项，`ln.Close()` + 关闭全部 tracked conns，恒回 `ok:true`。Status：`{Tunnels: len(tunnels)}`。slog.Debug 记录开/关。**不做服务端 token 校验**——但须写明信任边界：控制通道无鉴权，任何能连 gRPC 的进程可令本插件向任意 `host:port` 发起外连（SSRF 面）。与既有宿主"一致"的只是无鉴权；本插件会**主动外连**，威胁模型不同，故以**默认 loopback 绑定收口**（`--addr` 不得暴露到 loopback 之外，除非先加鉴权；server.go 注释声明此边界）。

### 部署维度（同机为默认，异机不破坏契约）

`endpoint` 契约**本身不假定同机**——它就是一个任意可达 `host:port`，GOST 侧只 `net.Dial`，监听地址完全由插件决定。同机部署（默认）：bind `127.0.0.1`，无暴露面、无防火墙改动（与 gost-plugins 的进程同机惯例一致）。异机部署：`--bind` 配可达接口，`endpoint` 由 `ln.Addr()` 自然携带该 host，GOST 跨网拨号即通；运维点：每隧道动态端口需防火墙放行，严格网络下建议等真实引擎的持久隧道 / mux 复用（一条隧道一端口）再上异机。异机 + 数据面需原生加密 → 两个出口留待硬需求出现再选：① endpoint 上加 TLS listener、内层 dialer 取 `tls`（复用既有 TLS 配置管线，TCP 语义完整保留）；② 数据面改走 gRPC 双向流（复用 `x/dialer/grpc` 既有实现；**优势**：单端口防火墙即可放行、插件宿主入站受 NAT/防火墙限制时数据面继承已建立控制连接的连通性（B 语义=endpoint 为会话凭证，见"扩展性契约"）；**代价**：流 conn 无 deadline / `ApplyKeepalive` 静默失效 / 控制数据同生共死，这些在真实网络跳上比 loopback 更痛，见记忆）。

### C. `x/` 模块 — p2p 组件 + 节点解析接线（无新增 dialer，无 core 改动）

| 文件 | 内容 | 镜像 |
|---|---|---|
| `x/p2p/plugin/grpc.go`（新） | `type TunnelProvider interface { OpenTunnel(ctx, peer) (id, endpoint string, err error); CloseTunnel(ctx, id) error; Close() error }`；`NewGRPCPlugin(name, addr string, opts ...plugin.Option) TunnelProvider`——构造形状镜像 recorder 宽松（连接失败记日志、恒返回非 nil provider），但**运行语义 fail-closed**：nil client / 端点拨不通 → `OpenTunnel` 返回错误，绝不 no-op（区别于 bypass/admission/recorder 的 fail-open/no-op） | `x/recorder/plugin/grpc.go`（构造）；fail-closed 反向：hop/rewriter |
| `x/p2p/tunnel_dialer.go`（新） | `newTunnelDialer(inner dialer.Dialer, pr TunnelProvider) dialer.Dialer`：实现 core `dialer.Dialer`（`Init` 转发 inner；`Dial` 按上节伪码——tunnelConn 在合成底座层创建、inner 返回值原样透传不二次包装；**实现 `dialer.Handshaker` 转发 inner**，tls/ws/mtls/mws/mtcp 的握手全在其 `Handshake` 方法，`x/dialer/tls/dialer.go:76`；`Multiplex()` 委托 inner 若实现 `dialer.Multiplexer`）；同文件 `SupportedDialer(name string) bool` 白名单（前置 3）；`tunnelConn` 同文件（`sync.Once`-Close + 幂等 `CloseTunnel`，**开/关均用新 ctx+short timeout**） | 合成底座思路：`x/dialer/grpc/dialer.go` 的 `options.Dialer` 用法；接口转发模式：`x/hop/plugin/grpc.go` 的断言式委托 |
| `x/registry/p2p.go`（新） | `func P2PRegistry() registry.Registry[x_p2p.TunnelProvider]`（实例注册，存 `NewGRPCPlugin` 产物） | `x/registry/recorder.go` |
| `x/config/config.go`（改） | 顶层 `P2Ps []*P2PConfig` + `P2PConfig{Name, Plugin PluginConfig}` | 同文件 `Recorders` 段 |
| `x/config/parsing/p2p/parse.go`（新） | `ParseP2P(cfg)`：默认 grpc → `NewGRPCPlugin(name, plugin.Addr, TokenOption, TLSConfig)`；type=http → 弃用日志 | `x/config/parsing/recorder/parse.go` |
| `x/config/parsing/parse.go`（改） | 常量 `MDKeyP2P="p2p"`（单键，值=插件名） | 同文件 MDKey* 常量 |
| `x/config/parsing/node/parse.go`（改） | 节点 metadata `name := mdutil.GetString(md, MDKeyP2P)`；`name==""` 跳过；否则 `provider := registry.P2PRegistry().Get(name)`，为空 → 报错 `unregistered p2p: <name>`；内层 dialer 须过白名单 `p2p.SupportedDialer(dialCfg.Type)`（前置 3），否则报错 `dialer %q does not support p2p`；`d = newTunnelDialer(d, provider)`（**置于既有 `d.Init(dialerCfg.Metadata)` 之前，`parse.go:272`**，wrapper.Init 转发内层 = 全链路只 Init 一次）后既有 `d.Init`/`NewTransport` 照旧 | — |
| `x/config/loader/loader.go`（改） | 新 `p2ps` 段：iterate `cfg.P2Ps` → `ParseP2P` → `registerGroup(entries, registry.P2PRegistry())` | 同文件 recorder 块（~242 行） |
| `x/p2p/plugin/grpc_test.go`（新） | 聚焦测试（见下） | 包内 fake server（`x/recorder/recorder_test.go` 风格） |

**接线次序关键点**：p2p 包裹发生在 `ParseNode` 解析出 dialer 之后、**既有 `d.Init` 之前**（`x/config/parsing/node/parse.go:272`）——`d = newTunnelDialer(d, provider)` 后既有 `d.Init`（wrapper.Init 转发内层）/`NewTransport` 照旧，全程只 Init 一次。适配器不重做握手：内层握手经 `Transport.Handshake` 对 `dialer.Handshaker` 的类型断言触发（`x/chain/transport.go:59`），wrapper 实现并转发（见"内层协议与 mux"）。与 route-splitting（`x/chain/chain.go:152` `Multiplex()` 子路径嵌入）不冲突：桩下内层 tcp → `Multiplex()=false`；且隧道即"基础通路"，链前路径不再叠加（语义正确：p2p 取代到达节点的网络路径）。

### D. `gost/` 模块 — 无改动

p2p 组件经 config/loader 注册（同 recorder），无 `init()` 注册、无需空导入，`gost/cmd/gost/register.go` 不动。

### E. `play/` — 演示配置（新 `play/p2p.yaml`）

```yaml
p2ps:                                    # 命名 p2p 插件组件（同 recorders:）
  - name: p2p-1
    plugin:
      type: grpc
      addr: 127.0.0.1:8003              # p2p 宿主 repo gRPC 地址
      # token: gost
services:
  - name: service-0
    addr: :8080
    handler:
      type: auto
      chain: chain-0
    listener:
      type: tcp
chains:
  - name: chain-0
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: 127.0.0.1:18080        # "peer"：桩桥接目标（对端 GOST HTTP 转发代理端口）
            connector:
              type: http                 # 显式：connector 由对端协议决定
            dialer:
              type: tcp                  # 普通 tcp dialer——协议即底座之上的内层
            metadata:
              p2p: p2p-1                 # 单键声明：本节点基础通路走 p2p 插件 p2p-1
log:
  level: debug
```
（config-validator 只查 forwarder 协议/chain/hop/auther 引用与必填字段，`p2p:` 节点 metadata 与 `p2ps:` 段不拦截，已确认可通过。`-F` CLI 可经节点 metadata 声明：`-F "http://127.0.0.1:18080?node.p2p=p2p-1"`，但需同时 `-C` 一个含 `p2ps:` 的定义——YAML 演示为主，CLI 属可选核验。）

**本里程碑内层 dialer 只验证 `tcp`**（无握手路径，wrapper 全链路完整跑通）；tls/ws/mtls/mws 需补完"内层协议与 mux"三条前置后用同类三终端流程另验（peer 侧起对应 listener）。

> **验证结果注记（2026-09-05 mux/token 里程碑）**：白名单已扩至 `tcp/tls/ws/mtcp/mtls/mws`（`x/p2p/tunnel_dialer.go`），wrapper 已转发 Handshaker，TLS ServerName 走既有 `node/parse.go` 的 `SplitHostPort(cfg.Addr)` 兜底（p2p 下 node addr 即 peer，与非 p2p 语义一致，无需改代码）。mux 形态：**隧道惰性开洞**（`OpenTunnel` 下沉进 `tunnelBaseDialer`——mtcp 缓存命中时不碰 base，否则每 Dial 漏一条孤儿隧道），一条隧道 = 一个 mux 会话 = N 条流，会话死亡经 `session.conn.Close()` → `CloseTunnel` 回收。控制通道 token 校验已补宿主侧（`p2p --token` + gRPC metadata，常量时间比对）。演示配置：`play/p2p-tls|ws|mtcp|mtls.yaml`。

### 分层认知（适配器=建底座管道，dialer=在管道上握手，connector=在管道上说话）

p2p 适配器是 reach 面：对插件发 control RPC（OpenTunnel）→ 拨本地 endpoint → 产出 `net.Conn` 底座（经插件桥接连到对端 peer）；内层 dialer 在底座上做协议握手（tls/ws/mux）；connector 是 speak 面：在第 3 层做代理协议握手（HTTP CONNECT/SOCKS5/透传），只与"对端跑什么协议"相关，**永远看不到插件/endpoint**。core 只消费普通 conn，不感知 P2P。隧道是昂贵资产：本桩为"每 Dial 一隧道"的最简形态，未来里程碑在底座之上用内层 mux dialer 复用（一条隧道 = mtcp/mtls 会话 = N 条 stream；wrapper 只供底座，mux 生命周期归内层，connector=每连接服务）。

### connector 选型说明（回答问题"插件配 http 是否不合适"）

connector 与 p2p 插件**正交**：它只由隧道对端是什么决定，p2p dialer 仅替换"到达该对端的网络路径"。demo 对端是 GOST HTTP 转发代理节点，配 `http` 是正确且必要的（http connector 在隧道上做 HTTP CONNECT 握手）。若对端是 SOCKS5/relay 节点则改配 `socks5`/`relay`——纯配置，证明与插件机制无关。**唯一不合适的语义**：隧道直达对端某服务端口（tailcat 端口映射模型，对端非代理节点），那时应配 `tcp` 透传 connector（`x/connector/tcp/connector.go`：`return conn, nil`，无握手）而非 http。`direct` connector 不是透传（忽略隧道 conn、绕链重拨目标，`x/connector/direct/connector.go:58`）。**未来决策点**："tunnel-to-destination" 语义是否引入、以何种形式（tcp 透传 connector / 端口映射），本桩不实现。

## 测试设计（`x/p2p/plugin/grpc_test.go`，包内测试）

**不放 gost-plugins 依赖进 x**（x 不依赖 gost-plugins，方向倒置；x/CLAUDE.md 现"无测试"为现状描述——本测试作为模块内第一个聚焦测试，跑通即价值）。测试内联 fake gRPC server（实现同契约：tunnels map + 每隧道 listener + 桥接 goroutine，约 70 行）+ fake echo target；用 `NewGRPCPlugin(name, fakeAddr)` 建 provider，`newTunnelDialer` 包一个 `tcp` dialer 再 `Dial`。

用例：
1. `TestDialRoundTrip`——`Dial(ctx, targetAddr)` → 经桥接回环读/写；OpenTunnel 计数 1→返回 conn `Close()`→0；二次 Close 幂等。
2. `TestPluginDown`——addr 指向已关闭端口 → Dial 报错（fail-closed：非 no-op）。
3. `TestLocalEndpointDead`——fake 返回已关闭端口 endpoint → Dial 报错且隧道计数归零（清理路径验证）。
4. `TestDialConcurrent`——8 goroutine 并发 dial/echo/close，全过、终计数 0（race 覆盖）。
5. `TestOpenTunnelInvalidPeer`——peer 非 host:port（如 `foo`）→ Dial 报错（契约校验只走 gRPC status；覆盖单一失败通道）。
6. `TestOpenTunnelBizFail`——fake 对合法 peer 回包体 `ok:false` + error → Dial 报错且计数归零（业务失败通道）。
7. `TestHandshakeForward`——inner 用实现 `dialer.Handshaker` 的假 dialer 包 `tunnelDialer` → 断言 `tunnelDialer.(dialer.Handshaker)` 成立且转发 `AddrHandshakeOption`（防回归：内层握手必须被触发，评审实锤的缺陷）。
8. `TestSupportedDialer`——`SupportedDialer("tcp")==true`、`SupportedDialer("kcp")==false`（前置 3 白名单回归；ParseNode 报错路径属 config 层，随接线验证）。

## 端到端手动验证（play/p2p.yaml + 真实二进制）

```bash
# 终端 A — "对端"：真实 gost 代理（其监听端口即桩桥接目标）
cd gost && go run ./cmd/gost -L "http://:18080"
# 终端 B — p2p 宿主（桩，独立 repo）
cd p2p && go run . --addr :8003
# 终端 C — 客户端（p2p 链）
cd gost && go run ./cmd/gost -C play/p2p.yaml
# 验证数据面穿透桩：8080 → tcp dialer（底座经 p2p 适配器→插件隧道）→ 桥接 → 18080 → 目标
curl -x http://127.0.0.1:8080 http://example.com/
```
日志中应对应看到 peer 侧连接、插件 OpenTunnel/Close 的 slog.Debug；curl 成功即缝隙跑通。可选 `-F` CLI 形态核验（节点 metadata 声明，需 `-C` 提供含 `p2ps:` 的配置）：`go run ./cmd/gost -C play/p2p.yaml -L "http://:8081" -F "http://127.0.0.1:18080?node.p2p=p2p-1"`（`node.` 前缀 query 进节点 metadata）。

## 验证清单

```bash
cd plugin && go build ./... && go vet ./...          # proto + 生成物
cd p2p && go build ./... && go vet ./...        # 宿主 repo
cd x && go build ./... && go vet ./...               # p2p 组件/接线编译
cd x && CGO_ENABLED=1 go test -race ./p2p/... -v     # 聚焦测试 race 干净
cd gost && CGO_ENABLED=0 go build ./cmd/gost/... && go vet ./cmd/gost/...
# 然后上述三终端 + curl 手动演示
```

## 发布顺序与风险

1. **模块依赖链**：plugin 模块发 tag（如 v0.5.1）后，需在 x 与 p2p repo 用 `go get github.com/go-gost/plugin@<tag>` 升 pin（x 现 pin v0.5.0）；gost-plugins 无关本次。**go.mod 直改被 hook 拦截**，只能走 go get/go mod tidy。go.work 内本地构建不受影响（`./p2p` 加入后）；x 与 p2p repo 的独立构建在 tag 发出前会碎——先并排提交（plugin → x → p2p），符合 core→x→gost 发布顺序惯例。
2. **生成物**：生成代码永远提交生成物、不手改；不要为 p2p 跑 `go mod tidy`（plugin 模块旧 require 会无谓抖动）。
3. **不做的（本里程碑明确排除）**：DERP/rendezvous、打洞、data 面走 GostTunel gRPC 流（决定已锁：本地 TCP）、HTTP 插件变体、服务端 token 校验、control 通道 TLS、tunnel-to-destination（final-hop `direct` 接线，`x/connector/direct/connector.go:58`）、**x/api 的 /config CRUD 与 metrics 不覆盖 `p2ps:`**（命名组件注册不进 Web API，留到真实 p2p 引擎里程碑集成）、版本号 bump。
4. **gofmt**：.claude/settings.json 提交钩子自动 gofmt；生成物已 gofmt 干净。