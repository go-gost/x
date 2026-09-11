# go-gost/gost#642 — UDP 目的端口范围跳跃: 可行性 & 复杂度分析

## 需求

客户端支持 UDP 目的端口范围跳跃 (destination port-range hopping)，类似 Hysteria 的端口跳跃机制:

```
# 期望的客户端语法
gost3 -L=udp://:8000/mydomain.com:50000-50050/?hopInterval=x秒
gost3 -L=:1080 -F=kcp://127.0.0.1:8000

# 服务端用 iptables 将端口范围折叠到单一端口
iptables -t nat -A PREROUTING -i ens3 -p udp --dport 50000:50050 -j DNAT --to-destination :51000
gost3 -L=kcp://:51000
```

核心用例: 端口跳跃 evasion → iptables 服务端范围折叠 → KCP/QUIC 隧道 → 透明代理。

## 现有基础设施

### 1. `AddrPortRange` — 目的端口范围已可解析

[x/internal/net/addr.go:100](x/internal/net/addr.go#L100) 中 `AddrPortRange.Addrs()` 会将 `50000-50050` 展开为 51 个独立地址 `[":50000", ":50001", ..., ":50050"]`。

[x/config/cmd/cmd.go:440-499](x/config/cmd/cmd.go#L440) 中 `buildServiceConfig()` 将这些地址转化为 `ForwardNodeConfig` 条目。当只有 1 个 listener 但 N 个 forward node 时，所有 N 个 node 都会附加到同一个 service 的 `ForwarderConfig` 上 (一个 hop 持有 N 个 target)。

**关键缺漏**: selector 策略 (`RoundRobin`, `Random`, `Hash`, `FIFO`) 是 per-association / per-connection 的，**不支持基于时间的旋转**。所以要实现"每 X 秒跳跃端口"，需要时间感知的选择逻辑。

### 2. UDP forwarder 的 relay 路径

UDP forwarding 由 `x/handler/forward/local/` 处理 (注册名为 `"udp"`, `"tcp"`, `"forward"`):

- **connected UDP** (`handleRawForwarding`): 一次 `dialTarget()` → 单次 `Router.Dial()` → 双向 pipe。目标地址由 hop.Selector 选出，在 association 生命周期内固定。
- **stateless UDP** (`handleRawDatagram`): 每个 datagram 做一次 `dialTarget()` → `ReadFrom` → `WriteTo` → `ReadFrom` → `WriteTo`。从技术上讲，dest port **可以 per-datagram 改变**，但当前 selector 不提供 per-datagram 旋转。

[x/handler/forward/local/forward.go:32-175](x/handler/forward/local/forward.go#L32)

### 3. KCP 会话身份绑定到 4-tuple

xtaci/kcp-go 库 (`v5.6.5`) 的会话模型:

| 组件 | 机制 | 端口跳跃的影响 |
|------|------|---------------|
| **服务端 `Listener`** | 会话存储在 `map[string]*UDPSession`，key 为 `remoteIP:Port` 字符串 | 若客户端源端口稳定 → 同一 session。symmetric NAT 下失效。 |
| **客户端 `output()`** | 固定 `msg.Addr = s.remote`（dial 时解析的地址） | 必须通过 PacketConn wrapper 重写目标端口才能跳跃。 |
| **客户端 `readLoop`** | 锁定到第一个看到的源地址；丢弃所有来自不同地址的包 | 服务端始终从 `:51000` 回复（真实端口，非跳跃范围端口），所以稳定。只有服务端回复时源端口变化才会出问题。 |

### 4. QUIC 支持连接迁移

GOST 的 QUIC 传输使用 quic-go，天然支持 QUIC Connection IDs。这些 ID 允许会话在客户端的 IP/端口变更后依然存活 (RFC 9000 连接迁移)。所以 **QUIC 对 symmetric NAT 也具有较高鲁棒性。**

但 QUIC listener 和 KCP listener 一样，只绑定到**一个端口**。跳跃仍然是面向**服务端的监听端口**的，因此需要 iptables 折叠范围，或者在 gost 内支持多端口 QUIC listener。

## 可行性: 三个方案层级

### 方案 A: 传输层跳跃 (推荐) — 中等工作量

**机制**: 用 PacketConn wrapper 包装 KCP/QUIC dialer 的 `net.PacketConn`，在 `WriteTo` 中根据当前跳跃端口重写目标端口。底层库 (kcp-go/quic-go) 不知道端口在跳跃。

**数据通路**:
```
客户端 KCP dialer 创建 PacketConn → hopWrapper.WriteTo(addr) 重写端口 → kcp-go output() 向 hopped 端口发包
服务端 iptables dport 范围 → 折叠到 :51000 → KCP listener 收到 → 按客户端源 IP:Port 关联会话
服务端从 :51000 回复 → 客户端 readLoop 收到稳定源地址 (一直是 :51000)
```

**需要修改的地方**:
1. **配置解析** (`x/config/cmd/cmd.go` / `x/config/config.go`): 为 `ForwardNodeConfig` 添加 `PortRange` + `HopInterval` 字段，或扩充 chain/hop 的 metadata。
2. **KCP dialer** (`x/dialer/kcp/dialer.go`): 若配置了跳跃参数，将 `kcp.NewConn` 传入的基础 `net.PacketConn` 用 `portHoppingConn` 包装。
3. **QUIC dialer** (`x/dialer/quic/dialer.go`): 同上，但这边的 `quic.DialEarly` 使用的是包装过的 PacketConn。
4. **PortHoppingConn** (新文件/复用 `x/internal/net/` 内现有工具): 一个实现了 `net.PacketConn` 的 wrapper:
   - 持有 `currentIndex atomic.Int32` 用于在范围端口间轮转
   - 每 `hopInterval` 秒递增 `currentIndex`
   - `WriteTo(b, addr)` → 用 `currentPort()` 重写 `addr.Port`，委托到底层 `PacketConn.WriteTo`
   - `ReadFrom` / `Close` / `LocalAddr` → 直透传到底层

**KCP 的注意事项**: symmetric NAT（为不同的目标端口分配不同的源端口）会导致服务端因为客户端的 `addr.String()` 变化而创建新 KCP 会话 → 连接中断。这是 KCP 的基本限制，无法在 gost 代码层面解决。**QUIC 没有这个问题**，因为连接 ID 的存在使得源端口变化也没问题。

**工作量**: 预估约 200-300 行新代码 / 约 5 个文件。

### 方案 B: Stateless UDP forwarder 跳跃 — 小工作量

**机制**: 只为 plain-UDP forwarding（非隧道）添加时间跳跃。已经在现有的多 node forwarder (方案 A 的步骤 1) 基础上完成了一半。

**数据通路**: `handleRawDatagram` 中的每次 `dialTarget()` → 当前端口 → `WriteTo`

**限制**: 仅适用于 plain-UDP relay，**不适用于 KCP/QUIC 隧道**，而隧道才是 evasion 真正需要的地方。

**工作量**: 约 50-100 行新代码 / 2-3 个文件。

### 方案 C: 完全协议重设计 — 超大工作量

机制: 不带 iptables 的原生会话迁移，fork / 修补 kcp-go 让会话按 Conversation ID 查找，多端口 listener，迁移信令。这正是 ginuerzh 在 [这条评论](https://github.com/go-gost/gost/issues/642#issuecomment-2568987717) 中提到 "需要新协议和流程" 时的设想。

**工作量**: 数周，跨多个仓库 (fork kcp-go，新认证流程，多 socket 监听)。

## 建议

**方案 A (传输层 PacketConn wrapper)** 是正确的中位数: 用约 200-300 行代码和简单的 PacketConn wrapper，为 KCP 和 QUIC 隧道实现真实的端口跳跃，服务端无需改动 (只需 iptables)。

回应 issue 时，需要解释以下几点:
1. 已实现用途: `AddrPortRange` 已经能将目标端口范围展开为多个 forward node。
2. 未实现部分: 时间感知跳跃，推荐用方案 A 实现。
3. KCP 限制: 服务端 symmetric NAT 会导致跳跃连接中断。建议用 QUIC 传输以获得完全的鲁棒性。
4. 服务端: iptables DNAT 是跨越端口范围的最轻量方案；不需要在 gost 服务端做任何改动。

## 验证

如果决定实现: 不具备 ci/macos 下自动化测试的大规模开销价值。手工验证:
```bash
# 服务端
iptables -t nat -A PREROUTING -p udp --dport 50000:50050 -j DNAT --to-destination :51000
gost -L=kcp://:51000

# 客户端 (运行需要方案 A 的二进制)
gost -L=:1080 -F=kcp://server:50000-50050?hopInterval=10s

# 通过代理发起 UDP 连接，验证 10 秒后目标端口变化 (tcpdump)
```
