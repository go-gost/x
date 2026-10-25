# 多 IP 候选的拨号失败转移（chain 节点地址）

- 日期：2026-10-25
- 范围：`x/internal/net/resolve.go`、`x/chain/route.go`、`x/chain/addr.go`（不改 `core/`）
- 结论一句话：**`Resolve` 只取 `ips[0]` 让 hosts/resolver 的多 IP 形同虚设；改成保留候选、健康候选间随机分散、失败候选短期降权、逐个拨号。**

## 现状

- `xnet.Resolve`（`x/internal/net/resolve.go:38`）在 hosts 命中或 resolver 返回后都只取 `ips[0]`，返回单个 `IP:port`。
- 调用点：`chain/route.go:233`（首跳节点地址）、`chain/route.go:277`（后续跳）、`chain/router.go:132`（目标地址）。
- 后果：hosts 里写多行没有容错；实际用哪个 IP 取决于 redis set 的顺序（无序但稳定），一旦那个 IP 不可达，所有新建连接失败，节点连续失败 `maxFails` 次后整条链进入 `failTimeout`。
- 与 `getaddrinfo` + `connect` 的语义不一致：系统会依次尝试所有地址，gost 提前塌缩了候选。
- 反例：`handler/dns/handler.go:409` 是把 hosts 命中的**所有** IP 写进 A/AAAA 响应，同一个 `gost:hosts` 在 DNS 面和代理链路面的行为不同。

## 目标 / 非目标

- 目标：
  1. 节点地址的拨号在候选 IP 之间失败转移；
  2. **保留多 IP 的负载均衡**——健康候选之间均匀随机，不能退化成"永远用第一个"的主备模式；
  3. 一个坏 IP 不能每条新连接都吃满一次拨号超时。
- 非目标：不改目标地址（`router.dial` 的 `ipAddr`）的选路语义；不做并发竞速（happy-eyeballs）；不改 `core/`；后续跳（hop≥1）不做失败转移。
- 反目标：让 `Chain.Route()` 的选路因 IP 抖动而变化——随机只发生在 `connect()` 内部，`Resolve` 仍返回确定性的首个候选。

## 方案

1. **新增 `xnet.ResolveAll(...) ([]string, error)`**：hosts 命中 → 全部 IP；否则 resolver → 全部 IP；两者都没有 → `[]string{addr}`（保持原样，交给下游 dialer）。去重。`Resolve` 改为「取 `ResolveAll` 的第一个」，其余调用点行为不变。

2. **`chainRoute.connect` 首跳按顺序逐个候选 `Dial` + `Handshake`**，第一个成功即用；全部失败才 `marker.Mark()`（只 Mark 一次）并计错误。`MetricNodeConnectDurationObserver` 仍观测整段。

3. **候选排序（`x/chain/addr.go`）**：把候选分成「TTL 内失败过的」和「健康的」两组；健康组 `rand.Shuffle` 后在前，失败组在后（失败组内部也洗牌，全组都失败时仍有随机性）。这样：
   - 全部健康 → 均匀分布，保留多 IP 的负载均衡；
   - 有坏 IP → 它只在 TTL 窗口内被排到后面，窗口过后重新参与轮换（顺带探测恢复）。

4. **失败记忆**：包级 `sync.Map`，key = `node.Addr + "|" + candidate`，value = 失败时间；命中时用 `timeNow()` 判断是否超过 `addrFailTTL`（30s）。拨号成功则删除该 key（立即恢复参与轮换）。

5. **后续跳（hop≥1）暂不做**：`Connect` 复用上一跳的 stream，失败后在同一条 conn 上重试有 desync 风险，正确做法是重建整条链，单独评估。

## 权衡

- 坏 IP 的代价：TTL 窗口内，每条新连接有 ~1/N 的概率先撞上它（N=2 时约 50%）；撞上时付一次拨号超时再转移，之后该候选被降权，直到 TTL 到期再探一次。相比"永远用第一个"，最坏情况从 100% 降到 TTL 窗口内的一次探测。
- 为什么不用 last-good（记住上次成功的候选）：那就是主备模式，健康时也永远只用同一个 IP，丢掉多 IP 的负载均衡——这是被明确否掉的方向。
- 随机只在 `connect()` 内部：`Resolve` 的返回值仍参与 `Chain.Route()` 的分流判定，保持确定性。
- key 用 `node.Addr` 而非节点指针：配置热重载后节点对象会重建，按指针存会失效或泄漏；按地址存可跨重载保留，规模受配置约束。

## 验证

- 单测（`x/internal/net`）：`ResolveAll` 的 hosts 多 IP / 去重 / resolver 多 IP / 两者皆无 / `ip4` 过滤 / `ErrInvalid` / 空结果报错 / 空地址。
- 单测（`x/chain`）：假 Transport + 假 HostMapper
  - 第一个候选失败 → 第二个成功，且两个都被拨过；
  - 失败候选在下一次连接中被降到最后（健康候选仍随机在前）；
  - TTL 过期后失败记录失效（用可替换的 `timeNow`）；
  - 全部失败 → 返回错误且 `Marker().Count() == 1`；
  - 成功拨号清除该候选的失败记录。
- 手工回归：pi 上 `relay.gost.run` 两个 Cloudflare IP 的真实链路，观察两条 IP 都有流量（负载均衡未退化）。

## 我替你定的（可推翻）

- `addrFailTTL = 30s`（包级 var，测试可改）。
- 失败记忆 key 用 `node.Addr + "|" + candidate`。
- 失败转移只覆盖首跳；后续跳留作后续。
