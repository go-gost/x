# P2P M2: STUN + UDP 打洞直连（KCP + smux，relay 先行后台升级）

## Context

DERP 中继里程碑（d3797f7）已打通跨机隧道，但流量全走中继。M2 引入直连：peer 间先经中继建立会话（零新增首拨延迟），后台并行 STUN + UDP 打洞，直连建成后新流走直连、旧流继续跑中继，打洞失败/直连断时静默回退中继。四个设计分叉已与用户敲定（2026-09-07）：

- **可靠层 = KCP + smux**：`kcp-go/v5 v5.6.5`（x/ 同款、gost 验证多年）上叠 smux——p2p 现有会话机制（角色按公钥序、accept 循环、OpenStream）原样复用，只换 smux 之下的传输；QUIC 需两套会话栈且依赖重，弃。
- **升级策略 = relay 先行 + 后台打洞**。
- **STUN = derper 自带**（`-stun` 默认开，:3478），p2p 加 `--stun` 可覆盖。
- **单里程碑**，内部任务分阶段，一次验收。

数据面 seam 不变（[[p2p-data-plane-seam]]）：OpenTunnel → 本地 TCP endpoint，GOST/x 零改动。discovery 里程碑已否决（[[p2p-derper-no-presence]]：真 derper 不给开放中继客户端发 PeerPresent），本里程碑与其无关，唯一复用的是它留下的**包级控制帧**思路（候选交换需要控制面通道）。

## 关键事实（已验证）

- **kcp-go v5 API**（模块缓存 `kcp-go/v5@v5.6.5/sess.go` 实测）：`NewConn3(convid, raddr, block, dataShards, parityShards, conn net.PacketConn)` = 客户端在**现有 socket** 上建会话；`ServeConn(block, shards, conn)` = 服务端在现有 socket 上监听。→ STUN 探测与 KCP 会话共用同一 UDP socket，端口相关型 NAT 下映射一致。
- **derper 自带 STUN**：`-stun` 默认 true、`-stun-port` 3478，绑定同 IP。e2e 现有脚本跑 `-stun=false`（保持 relay-only 回归路径）。**实测发现**：derper 的 STUN 只应答 Tailscale 方言（binding 请求须带 `SOFTWARE="tailnode"` + 尾置 `FINGERPRINT` 属性，普通 RFC 5389 请求被静默丢弃）；且 `-a :443` 通配时 STUN 绑 `[::]:3478`（IPv6-only），IPv4 默认 `--stun` 打不到——derper 须显式 `-a <ip>:443` 或 p2p 显式 `--stun`。
- **PR#263 原型**（[[p2p-pr263-reference]]）：STUN 外部地址 + 最小 UDP 打洞 + 可靠层三件套的可行性证明；IRC 信令不可取。
- **x/dialer/kcp 先例**：gost 自己就是 smux-over-kcp（`kcp-go/v5` + `smux` 同仓）。
- **控制帧先例**：e28becd（已 revert）实现过 `[type 1B][payload]` 包级分帧（pump 分流 + Write 预置 type），M2 复活其分帧部分，presence/svc/announce 部分保持删除。
- **反欺骗原语已在手**：`derpclient` 的 `PrivateKey.SealTo(PublicKey, cleartext)` / `OpenFrom(PublicKey, ciphertext)`（nacl box，24B nonce 布局，见 derpclient.go）可直接把候选封到对端公钥、以 src key 验证来源——tailscale disco 反欺骗的同款思路，零新依赖。

## 设计

### 1. 控制面：包级帧复活（engine.go，derpclient 不动）

```
[type 1B][payload]
type 0x00 = 控制帧: [0x00][kind 1B][…]
    kind 0x02 = punch-candidates: 明文=[count 1B]([family 1B(4/6)][addr 4/16B][port 2B BE])*；封装=e.priv.SealTo(peerPub, 明文)（24B nonce + nacl box）
type 0x01 = 会话数据块（smux 字节流切片，Write 预置、pump 剥一次）
```

- pump 分流看 `pkt[0]`：0x00 → handleControl（进直连状态机）；0x01 → 剥 type 入会话队列；未知丢弃（前向兼容）。
- handleControl 收 kind 0x02 → `e.priv.OpenFrom(src, body)` 解封（24B nonce 在前，见 [[p2p-derp-relay-done]] 的 SealTo/OpenFrom 布局）；解封成功即证明候选来自 src key（反欺骗）、失败静默丢弃。候选经 derper 转发但内容只有两端可见、第三方无法伪造——tailscale disco 反欺骗 nonce 的同款思路，复用 derpclient 现有原语，非新密码学。
- 两端须同版本引擎（线路格式变更，宿主是新产物，可接受）。

### 2. STUN 客户端（新包 p2p/internal/stun，~100 行，仅 stdlib）

RFC 5389 binding request：20B 头（type 0x0001、magic cookie 0x2112A442、随机 12B transaction ID）→ 从**给定 UDP socket** 发往 STUN server → 解析 XOR-MAPPED-ADDRESS（0x0020，XOR cookie）→ 返回 `netip.AddrPort`。

- API：`stun.Lookup(ctx, stunAddr string, conn *net.UDPConn) (netip.AddrPort, error)`。
- 关键约束：必须从 punch socket 发出（同 socket 才保证 NAT 映射一致）。

### 3. 打洞状态机（新文件 p2p/direct.go，package main）

per-peer 直连状态：`none / attempting / up / backoff`。触发：relay smux 会话建立（`ensureSessionLocked` 成功后调 `maybeStartDirect(peer)`，两端各自触发、幂等收敛）。

一次尝试流程（A/B 双方，角色由公钥序决定，与 relay 会话同逻辑）：

1. 双方各建 `net.ListenUDP("udp4", :0)` punch socket。
2. 各用**自己的 socket** 发 STUN 得公网 ep；发候选帧 `[公网ep, 本地ep]` 给对方（本地候选服务同 NAT/同机直连）。
3. 收齐对方候选后：**key 小者 = KCP client** → `kcp.NewConn3(conv, peer公网ep, nil, shards, socket)`，SYN 重传即打洞探测；**key 大者 = KCP server** → `kcp.ServeConn(nil, shards, socket)` + 从同 socket 周期性发 dummy 探测包到对方候选（打开己方 NAT 映射、让 client 的 SYN 能进来；dummy 被对方 kcp Input 当垃圾丢弃）。
4. `conv` 由密钥对确定性派生（sha256(排序后的两公钥) 前 4 字节）——重试复用同 conv，无协商。
5. KCP 会话建立 → 其上起 smux（角色逻辑同 relay 会话：`roleIsClient` → smux.Client/Server(kcpConn)）→ `startAccept`。
6. 超时（punch 10s）未建成 → 关 socket、标记 backoff（30s）重试；期间新流全走 relay。

会话升级与回退：

- `OpenStream`：优先 `pc.direct` 的 smux 会话（存活则用），否则 relay 会话。升级对旧流无影响（旧流继续跑 relay 直到关闭）。
- 正常运行期 relay 会话**不拆**（fallback 保活）；直连断（kcp/smux close）→ 新流自动回退 relay + 安排重新打洞。
- **直连会话不依赖 DERP，derper 掉线不回收直连**：`teardown`（DERP 传输断开）只拆 relay 会话（client=nil、relay smux close），直连继续服务——这是 e2e「kill derper 直连不断」的前提。relay 重连成功后恢复 fallback；重新打洞需等控制面（relay）回来，故直连建立后、derper 掉线期间无法 re-punch（可接受）。
- 直连回收仅在：`engine.Close`（整机关闭）或直连会话自身 close（kcp/smux 死）。`pc.kill`/`teardown` 不回收直连。

### 4. 接线

- `main.go`：`--stun <host:port>`（缺省 = `--derp` URL 的 host + `:3478`；derper 默认开 STUN）。
- `engine.go`：分帧（T1）、`maybeStartDirect` 触发、handleControl → direct 状态机、OpenStream 优先直连。
- go.mod：`github.com/xtaci/kcp-go/v5 v5.6.5`（与 x/ 对齐）。

## 改动清单

### T1 控制帧复活（engine.go）
pump 分流 + `peerConn.Write` 预置 `0x01` + `handleControl`（kind 0x02，发侧 SealTo / 收侧 OpenFrom）——从 e28becd 照搬分帧，presence/svc/announce 不复活，候选封装/解封为本里程碑新增。

### T2 p2p/internal/stun/stun.go（新包）
binding request + XOR-MAPPED-ADDRESS 解析；`stun_test.go` 配进程内最小 STUN responder。

### T3 p2p/direct.go（新文件）
directState 状态机 + KCP client/server 角色 + dummy 探测 + smux-over-kcp + 回退/重试 + 回收。

### T4 接线
`--stun` flag、触发点、OpenStream 优先序、go.mod 加 kcp-go/v5。

### T5 测试（全部 -race）
- stun：进程内 fake STUN server 往返。
- direct：fake relay（现有 relayServer 扩展"可切换丢弃 0x01 数据帧"）+ fake STUN（返回回环候选）：直连建立后令 relay 丢弃数据帧 → 流仍通（证明走直连）；直连关闭 → 新流回退 relay 仍通；punch 超时路径（fake STUN 给不可达候选）→ 停留 relay 不崩。
- 回归：现有 8 用例全绿（分帧改动经过 pump/Write）。

### T6 e2e + 文档
- e2e：真 derper **开 `-stun`**（去掉 `-stun=false`），A/B 双宿主 + gost，curl 打通后 **kill derper** → curl 仍通（直连连续性证明）；`-stun=false` 跑现有 derp e2e 脚本（relay-only 回归）。
- 文档：p2p/CLAUDE.md（flag 表、架构、milestones 更新）、p2p/README.md、本 spec 文件。

## 已知边界（记录，不修）

- IPv4 打洞优先（候选帧带 family 字节为 v6 留位，本期不实现 v6 打洞）。
- 对称 NAT 打洞失败 → 永久 relay（周期重试，常量 30s）。
- KCP 链路无内建加密（透明性原则：内层 dialer mtls/tls/wss 才是保密门槛，与 DERP 同信任模型）。
- derper 部署须开 STUN（默认开）；`-stun=false` 部署静默保持 relay-only。
- 每次尝试新建 socket + STUN 查询（无缓存，规模小时无所谓；peer 多了再加共享 STUN 缓存）。
- 直连会话与 relay 会话并存：smux keepalive 流量在两条链路上都会持续。

## 验证

```bash
cd p2p && go build ./... && go vet ./... && GOWORK=off go build ./...
cd p2p && CGO_ENABLED=1 go test -race -count=1 ./...   # 新增 stun/direct 用例 + 8 既有全绿
# e2e：derper 开 -stun；B 宿主 + A 宿主 + gost；curl 打通 → kill derper → curl 仍通（直连证明）
#   回归：现有 /tmp/p2p-derp-e2e.sh（-stun=false，relay-only 路径）
cd x && go build ./... && git status --short            # x/ 零 diff 核验
```
