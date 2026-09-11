# TCP 嗅探新增 Redis 与 PostgreSQL 协议支持（两阶段）

## Context

GOST 当前的 TCP 嗅探框架（`x/internal/util/sniffing/` 与 `x/internal/util/forwarder/`）已支持 HTTP/1.x、HTTP/2、TLS（SNI 提取）、WebSocket 以及 SSH（仅检测，未处理）共 5 类协议。用户希望扩展应用层明文协议嗅探，使转发 handler 能够在"端口复用"场景下对**明文直连**的数据库流量做协议识别 + 首包元数据提取，进而用于路由决策和流量录制。

经调研行业做法（nginx `ssl_preread`/njs、HAProxy `payload` 字节匹配、Zeek/Suricata DPD、nDPI）与具体协议特征字节，确认 **Redis** 与 **PostgreSQL** 是最值得优先支持的两个协议：

- 二者均为**客户端先发包**（符合当前嗅探架构的 preread 模型），而 MySQL/SMTP 是服务端先发包，当前架构无法检测。
- 特征字节极稳定，不与现有 HTTP(`0x47/0x50`)、TLS(`0x16`)、SSH(`SSH-2`) 冲突。
- Zeek/nDPI/Suricata 均将二者列为核心检测协议，属于标准实践。
- 元数据对路由决策有实际价值：Redis 可按命令名路由、PostgreSQL 可按 `database` 路由。

**分两阶段交付**：第一阶段先完成 Redis（风险低、价值已论证、仅改 Peek(1)）；第二阶段再做 PostgreSQL（需要 Peek(8)，阻塞风险更高，独立验证）。两阶段独立 build + 集成测试，互不影响。

> 注意：`core/` 是框架基础接口层，按 CLAUDE.md 规定**不修改 core/**。所有改动在 `x/` 模块内部，复用现有 `sniffing`/`forwarder` 包。

---

## 目标行为

### 第一阶段（Redis）
1. 在嗅探路径中新增 `ProtoRedis` 常量，识别 RESP 首字节。
2. 解析 RESP 首命令，提取 `command`（如 `PING`/`AUTH`/`SET`/`GET`/`HELLO`）、`key`（首参数后的第一个 bulk 字符串）。
3. 将协议名写入 `ro.Proto`，元数据写入新增的 `ro.Redis` 子记录（仿 `ro.TLS` / `ro.DNS`）。
4. 通过 `hop.Select(ctx, hop.ProtocolSelectOption(ProtoRedis), ...)` 参与路由，可用 `protocol: redis` 把 Redis 流量导到专用 hop。
5. 透传：把已 read 的首包字节 replay 给上游，然后 `xnet.Pipe` 双向转发。

### 第二阶段（PostgreSQL）
1. 在嗅探路径中新增 `ProtoPostgres` 常量，识别 StartupMessage。
2. 解析 StartupMessage，提取 `database`、`user`、`application_name`。
3. 写入 `ro.Postgres` 子记录。
4. 通过 `protocol: postgres` 参与路由。
5. 透传同 Redis。

---

## 架构与改动点

### 0. 分层 Peek 重构（`x/internal/util/sniffing/sniff.go`）—— 两阶段共享

当前 `Sniff()` 单次 `Peek(dissector.RecordHeaderLen)`（5 字节）。盲目改成 `Peek(8)` 有**阻塞死锁风险**：客户端只发 <8 字节时（`bufio.Reader.Peek` 会等满 8 字节或 `sniffingTimeout`），与 [auto handler 的 SOCKS 死锁先例](x/handler/auto/handler.go#L102-L107) 同类。

**采用分层 Peek**：先 Peek(1) 检测可仅凭首字节判定的协议，再按需 Peek 更多。

```go
func Sniff(ctx context.Context, r *bufio.Reader) (proto string, err error) {
    // Tier 1: Peek 1 byte — 所有可仅凭首字节判定的协议在此判定。
    // Peek(1) 不会阻塞（除非连接真的一个字节都无）。
    b, err := r.Peek(1)
    if err != nil {
        return
    }
    switch b[0] {
    case '*', '+', '-', ':', '$':
        // Redis RESP type byte（第一阶段启用）
        return ProtoRedis, nil
    case 0x00:
        // PostgreSQL StartupMessage 首字节（第二阶段启用）——需 Peek(8) 校验 version
        hdr, err := r.Peek(8)
        if err != nil {
            return
        }
        if pgVersion := binary.BigEndian.Uint32(hdr[4:8]); pgVersion == 196608 || pgVersion == 196610 {
            return ProtoPostgres, nil
        }
        return
    }

    // Tier 2: Peek 5 bytes for TLS/HTTP/SSH（保持现有行为）
    // 第一阶段：case 0x00 在此进入 Tier 2（非 PG 的 0x00 session 罕见，与现行为无异）
    hdr, err := r.Peek(dissector.RecordHeaderLen)
    if err != nil {
        return
    }
    // TLS check → HTTP check (isHTTP) → SSH check（不变）
    return
}
```

**阶段划分**：
- **第一阶段**：Tier-1 仅启用 `case '*','+','-',':','$': return ProtoRedis`（Peek(1) 即返回，无 Peek(8)，零阻塞风险）。Tier-2 不变。
- **第二阶段**：在 Tier-1 增加 `case 0x00:` PG 分支（仅当 `byte0==0x00` 才 Peek(8)，PG StartupMessage 始终 ≥8 字节，不会阻塞）。Tier-2 不变。

**为何不在第一阶段预留 PG 分支**：保持第一阶段最小改动面。PG 分支是单个 `case`，第二阶段加一行即可，不破坏已稳定的 Tier-1 结构。

---

### 第一阶段：Redis

#### 1. 协议常量与检测（`sniff.go` 中 Tier-1 Redis 分支）

```go
const (
    ProtoHTTP = "http"
    ProtoTLS  = "tls"
    ProtoSSH  = "ssh"
    ProtoRedis = "redis"   // 第一阶段新增
)
```

Tier-1 `switch b[0]` 增加 RESP 标记分支（见第 0 节）。Redis 仅需首字节，`Peek(1)` 即返回。

#### 2. Redis 解析 + Sniffer 方法（新建 `x/internal/util/sniffing/sniffer_redis.go`）

**ParseRedisMetadata 签名**：`ParseRedisMetadata(r io.Reader, ro *xrecorder.HandlerRecorderObject) error`（导出，供 forwarder 包复用）。

调用方式必须精确镜像 `HandleTLS`：
```go
buf := new(bytes.Buffer)
if err := ParseRedisMetadata(io.TeeReader(conn, buf), ro); err != nil {
    return err
}
```

`io.TeeReader(conn, buf)` 消费恰好一个 RESP 消息并同时写入 `buf`，之后 `buf.WriteTo(cc)` 将首消息 replay 给上游。**这是 replay 正确性的唯一事实来源**：如果改用 `*bufio.Reader` 传给 ParseRedisMetadata，`buf` 不会被填充，replay 的数据为空/截断，上游服务端读到残缺流量。

解析行为：
- 读首个 RESP 消息（以 `*` 开头的行为 RESP 数组）。
- 格式：`*<n>\r\n` → 读 `n` 个 bulk string `$<len>\r\n<bytes>\r\n`。
- 第 1 个 bulk string = command（`strings.ToUpper` 存入 `ro.Redis.Command`，RESP 命令大小写不敏感）；第 2 个（若存在）= key（**保持原大小写**存入 `ro.Redis.Key`，Redis key 大小写敏感），后续参数丢弃（仅路由/录制不需要）。
- **关键约束**：解析器必须消费恰好一个完整的 RESP 消息，不得多读一个字节。RESP 数组的 `*<n>\r\n` 前缀提供了精确的消息边界（`n` 个 bulk string），确定性可控。
- 解析失败（非 RESP、截断）时返回 error，上层回退 raw forwarding（不丢连接）。

**Pipelined/多命令流量**：后续命令（消息 2..N）仍留在 `conn`（`br` 缓冲区 → 底层 `net.Conn`），`xnet.Pipe` 会将其完整转发给上游。因此 `AUTH + SELECT + GET` 三连发只解析 AUTH 用于路由，其余透明透传。**不需要**消费多消息或特殊处理 pipeline。

`(h *Sniffer) HandleRedis(ctx, network, conn, opts...)` 方法，与现有 `HandleTLS(ctx, network, conn, opts...)` 同形（`network` 参数沿用 sniffing 包约定）。实现：
1. `io.TeeReader(conn, buf)` 读取首包，`ParseRedisMetadata` 写入 `ro.Redis`。
2. 通过 `ho.dial`（handler 注入，同 HTTP/TLS）建立上游 `cc`。
3. `buf.WriteTo(cc)` 将缓存首包 replay 给 `cc`（仿 `HandleTLS` line 87-89）。
4. `xnet.Pipe(ctx, conn, cc)` 双向透传（含消息 2..N）。
5. 解析失败返回 error，调用方回退。

#### 3. forwarder 变体（新建 `x/internal/util/forwarder/sniffer_redis.go`）

与 `forwarder/sniffer_tls.go` 同构：实现 `HandleRedis`，内部复用 `sniffing.ParseRedisMetadata`（单一事实来源，forwarder 包只做拨号+路由包装）。

**路由集成**：forwarder 路径必须通过 `hop.Select` 传递 protocol 维度才能让 `protocol: redis` 选择器生效。参照 `resolveTLSNode`（[sniffer_tls.go:129](x/internal/util/forwarder/sniffer_tls.go#L129)），新建 `resolveRedisNode` 辅助函数：

- `resolveRedisNode(ctx, ro, ho)` → `ho.hop.Select(ctx, hop.ProtocolSelectOption(sniffing.ProtoRedis), ...)`

> sniffing 包路径（relay、http、sni handler）不需要 `resolveRedisNode`——它们的 dial 函数由 handler 注入，不做 hop 选择。

#### 4. recorder 子结构（`x/recorder/recorder.go`）—— 第一阶段仅 Redis

```go
type RedisRecorderObject struct {
    Command string `json:"command"`
    Key     string `json:"key"`
}
```

`HandlerRecorderObject` 新增字段（第一阶段仅 Redis；Postgres 字段第二阶段加）：
```go
Redis *RedisRecorderObject `json:"redis,omitempty"`
```

#### 5. handler 分派接入（5 处 dispatch，仅 Redis case）

5 处分派点分两类——**注入式 dial**（3 处，`sniffing.Sniffer`）和 **hop 选择式 dial**（2 处，`forwarder.Sniffer`）——各需不同的 HandleRedis。

**（A）注入式 dial**（3 处，`sniffing.Sniffer.HandleRedis`，签名含 `network`，无 hop）：

在 `switch proto` 中新增 `case sniffing.ProtoRedis`，调用 `sniffer.HandleRedis(ctx, "tcp", conn, sniffing.WithService(...), sniffing.WithDial(...), sniffing.WithBypass(...), sniffing.WithRecorderObject(ro), sniffing.WithLog(log))`。

- `x/handler/sni/sniffing.go:99` — `handleSniffedProtocol` 辅助方法（已有 HTTP/TLS case）
- `x/handler/http/connect.go:131` — HTTP CONNECT 隧道内 `sniffAndHandle()`，内联 switch
- `x/handler/relay/connect.go:234` — relay 隧道内 `handleConnect()`，内联 switch（最易遗漏）

> 这三处的 HandleRedis 不需要 `WithHop`——dial 闭包由 handler 注入（sni 通过 Router.Dial，http/relay 直接复用已建立的 cc）。

**（B）hop 选择式 dial**（2 处，`forwarder.Sniffer.HandleRedis`，签名无 `network`，有 `resolveRedisNode`）：

在 `handleSniffedProtocol` 的 `switch proto` 中新增 `case sniffing.ProtoRedis`，调用 `sniffer.HandleRedis(ctx, conn, forwarder.WithService(...), forwarder.WithHop(h.options.Hop), forwarder.WithBypass(...), forwarder.WithRecorderObject(ro), forwarder.WithLog(log))`。

- `x/handler/forward/local/sniffing.go:77` — `handleSniffedProtocol`（已有 HTTP/TLS case）
- `x/handler/forward/remote/sniffing.go:77` — `handleSniffedProtocol`（已有 HTTP/TLS case）

> 这两处的 HandleRedis 不接收 `network` 参数——现有 forwarder.HandleTLS 也无 `network`，保持一致。`resolveRedisNode` 内部使用 `"tcp"` 和 `sniffing.ProtoRedis`。

#### 6. 第一阶段验证

- `Sniff()` 对构造的 Redis（`*1\r\n$4\r\nPING\r\n`）首包返回 `ProtoRedis`；对 TLS/HTTP/SSH/非法首包返回正确结果（Redis 分支不影响现有协议）。
- `ParseRedisMetadata` 对真实首包提取正确 command/key，且底层 `bufio.Reader` 首包可完整 replay（下游能读到完整握手）。
- **Pipelined traffic**：`AUTH\r\nSELECT 0\r\nSET key val\r\n` ——仅首命令 `AUTH` 被解析用于路由/录制，后续 SELECT + SET 经 `xnet.Pipe` 透传到上游，`redis-cli` 端验证三条命令全部执行成功。
- `ro.Proto` 在所有 5 个 dispatch site 正确设置为 `"redis"`（验证方式：recorder 输出或 debug log 中各 site 的 `ro.Proto` 字段）。
- 对随机/非法首包返回 error，不 panic。
- 集成测试（`x/tests/e2e`，仿 `sniffing_test.go`）：起 `forward`/`tcp` 服务开 `?sniffing=true`，后端跑真实 Redis（Docker），用 `redis-cli` 连接断言 SET/GET 通、`ro.Proto=="redis"`、含 command 元数据、配置 `protocol: redis` 选择器能导到指定后端。
- 构建：`cd x && go build ./... && go vet ./...`

---

### 第二阶段：PostgreSQL

> 前置条件：第一阶段已合入且验证通过。

#### 7. 协议常量与检测（`sniff.go` 中 Tier-1 PG 分支）

```go
const (
    ProtoPostgres = "postgres"   // 第二阶段新增
)
```

Tier-1 `switch b[0]` 增加 `case 0x00:` 分支（见第 0 节）：仅当 `byte0==0x00` 才 `r.Peek(8)` 校验 version（`196608`/`196610`），避免 Peek(8) 阻塞。

#### 8. PG 解析 + Sniffer 方法（新建 `x/internal/util/sniffing/sniffer_postgres.go`）

`ParsePostgresMetadata(r io.Reader, ro *xrecorder.HandlerRecorderObject) error`：
- 与 Redis 阶段相同 pattern：`HandlePostgres` 内 `buf := new(bytes.Buffer)` + `ParsePostgresMetadata(io.TeeReader(conn, buf), ro)` → `buf.WriteTo(cc)` replay。
- 读 4 字节 length + 4 字节 version（确认 version = 196608 或 196610）。
- 读后续 KV 对（null-terminated 字符串），遇到 `user\0`、`database\0`、`application_name\0` 取其后 value 存入 `ro.Postgres.User` / `ro.Postgres.Database` / `ro.Postgres.ApplicationName`。
- 以末尾单个 `\0` 结束。
- 用 `io.TeeReader` + `buf.WriteTo(cc)` 缓存首消息并 replay。
- 解析失败返回 error 回退。

`(h *Sniffer) HandlePostgres(ctx, network, conn, opts...)` 方法，与 `HandleRedis` 同形。

#### 9. forwarder 变体（新建 `x/internal/util/forwarder/sniffer_postgres.go`）

实现 `HandlePostgres`，复用 `sniffing.ParsePostgresMetadata`。新建 `resolvePostgresNode`：
- `resolvePostgresNode(ctx, ro, ho)` → `ho.hop.Select(ctx, hop.ProtocolSelectOption(sniffing.ProtoPostgres), ...)`

#### 10. recorder 子结构（`x/recorder/recorder.go`）—— 第二阶段加 Postgres

```go
type PostgresRecorderObject struct {
    User             string `json:"user"`
    Database         string `json:"database"`
    ApplicationName  string `json:"applicationName,omitempty"`
}
```

`HandlerRecorderObject` 新增字段：`Postgres *PostgresRecorderObject \`json:"postgres,omitempty"\``

#### 11. handler 分派接入（5 处 dispatch，仅 Postgres case）

同第一阶段第 5 节 5 个文件，新增 `case sniffing.ProtoPostgres` 调用 `sniffer.HandlePostgres`。

#### 12. 第二阶段验证

- `Sniff()` 对构造的 PG（`00 00 00 24 00 03 00 02 ...`）首包返回 `ProtoPostgres`；PG 分支不影响 Redis/TLS/HTTP/SSH 检测。
- `ParsePostgresMetadata` 提取正确 database/user/application_name，首包可完整 replay。
- 集成测试：后端跑真实 PostgreSQL（Docker），用 `psql` 连接断言 SELECT 通、`ro.Proto=="postgres"` 含 database 元数据、`protocol: postgres` 选择器导到指定后端。
- 构建 + vet。

---

## 跨 repo 联动（仅标注，不在本计划执行范围内）

以下两个独立 repo 的改动**不在本计划各阶段的执行范围内**，仅作为联动项标注，由后续单独处理：

- `gost-plugins/recorder/recorder.go:125-134` 的 type 推断 `switch` 需加对应 `o.Redis != nil` / `o.Postgres != nil` case（否则 recorder 链路 type 字段缺失）。
- `inspector/pkg/model/record.go:81-107` 的 `HandlerRecorderObject` 需加 `Redis` / `Postgres` 字段（否则 inspector 展示缺失）。

> 注意：`x/` 模块内 `HandlerRecorderObject` 加了 Redis/Postgres 字段后，跨 repo 的 recorder/inspector 若未同步，会导致 JSON 解析/type 推断忽略这些字段。联动改动虽不阻塞 `x/` 构建，但应在对应阶段发布前补齐。

---

## 冲突分析（为什么 Tier 1 首字节检测不会误判）

| 协议 | 首字节 | 与 Redis/PG 检测的关系 |
|------|--------|------------------------|
| **Redis** (RESP) | `*`(0x2A), `+`(0x2B), `-`(0x2D), `:`(0x3A), `$`(0x24) | Tier 1 命中即返回 |
| **PG** (StartupMessage) | `0x00` | Tier 1 进入 Peek(8) 二次校验（仅第二阶段） |
| TLS | `0x16` | 不冲突：`0x16` ≠ RESP byte，≠ `0x00` |
| HTTP/1.x | `G/P/U/D/O/H/C/T` | 不冲突：均非 RESP 标记或 `0x00` |
| HTTP/2 | `PRI *` | byte0=`P`(0x50)，不冲突 |
| SSH | `SSH-2` | byte0=`S`(0x53)，不冲突 |

**关键安全论证**（第一阶段 Redis）：
- RESP 的 5 种类型字节 (`*`/`+`/`-`/`:`/`$`) 均不与 TLS(`0x16`)、PG(`0x00`)、SSH(`0x53`) 重叠。
- HTTP 方法首字母在 `0x41-0x54` 范围内，与 RESP 的 `0x24-0x3A` 不重叠。
- 唯一歧义点：`P`(0x50) 同时是 HTTP `POST`/`PATCH`/`PRI*` 和 Redis inline 命令 `PING` 首字节。但 `P` 不在 RESP type-byte 集合，走 Tier-2 后 `isHTTP()` 不匹配 `PING`，最终 `("", nil)` 走 raw forwarding。**正确行为。**

> 误判回退：非协议流量首字节恰好是 RESP marker → `Sniff()` 返回 `ProtoRedis` → `HandleRedis` 解析失败 → error → 调用方回退 raw forwarding。不丢连接（与 TLS 解析失败一致）。

---

## 已验证设计约束

本节记录代码审查中确认的关键事实，避免实施时重复验证。

### ProtocolSelectOption 无需修改 core/

`core/hop/hop.go:68-72` 已定义 `ProtocolSelectOption(protocol string) SelectOption`，设置 `SelectOptions.Protocol`（普通 string 字段，无枚举限制）。`resolveRedisNode` / `resolvePostgresNode` 直接传入 `sniffing.ProtoRedis` / `sniffing.ProtoPostgres` 即可，无需改动 `core/`。

### ro.Proto 赋值位置

所有 5 处 dispatch site 在调用 `Sniff()` 后**立即设置** `ro.Proto = proto`（已存在），HandleRedis / HandlePostgres 自身不设置 `ro.Proto`（与 HandleTLS / HandleHTTP 一致——TLS/HTTP sniffer 也不设置 `ro.Proto`）。见：

- `relay/connect.go:208`: `ro.Proto = proto`
- `http/connect.go:114`: `ro.Proto = proto`
- Forward local/remote + SNI handler: 在 `Sniff()` 后同样位置赋值

### 两个 Sniffer 类型的差异

| 特性 | `sniffing.Sniffer` | `forwarder.Sniffer` |
|------|-------------------|---------------------|
| 使用的 dispatch site | sni, http/connect.go, relay/connect.go | forward/local, forward/remote |
| HandleRedis 签名 | `HandleRedis(ctx, network, conn, opts...)` | `HandleRedis(ctx, conn, opts...)`（无 `network`） |
| 协议路由 | 不参与（`ho.dial` 由 handler 注入） | 通过 `resolveRedisNode` → `ho.hop.Select(...ProtocolSelectOption...)` |

**无需抽象统一**：现有 TLS/HTTP 已维持这个两包分裂模式（`sniffing.HandleTLS` vs `forwarder.HandleTLS`），Redis 按同样模式新增两个方法即可。

### relay/connect.go Sniff() 到达性

`relay/connect.go:207` 在写入 relay 响应 header（`resp.WriteTo(conn)`）后对原始 client conn 调用 `sniffing.Sniff()`，preread 字节通过 `br := bufio.NewReader(conn)` 缓存，再经 `xnet.NewReadWriteConn(br, conn, conn)` 传给 sniffer。`HandleRedis` 从该 conn 读取时，`br` 已含 preread 的 RESP 前缀字节。无需额外处理。

### PG Peek(8) 的安全性

`byte0==0x00` 才进入 Peek(8)——PG StartupMessage 始终 ≥8 字节（4 字节 length + 4 字节 version + 至少一个 `\0`），不会阻塞真实 PG 客户端。所有 dispatch site 在 Peek 前设置 `sniffingTimeout` 作为兜底保护。非 PG 客户端首个字节为 `0x00` 的概率在现实流量中可忽略。

### RESP command vs key 大小写

Redis 命令大小写不敏感 → `strings.ToUpper` 存入 `ro.Redis.Command`。Redis key 大小写敏感 → 保持原大小写存入 `ro.Redis.Key`。路由匹配时 `protocol: redis` 用于 hop 选择器，`command` 和 `key` 用于 recorder/日志，不做 key 的大小写归一化。

---

## 改动文件清单（精简）

### 第一阶段（Redis）
**sniffing 包（单事实来源）：**
- `x/internal/util/sniffing/sniff.go` — Tier-1 Redis 分支（Peek(1)）
- `x/internal/util/sniffing/sniffer_redis.go` — 新增（`HandleRedis` + `ParseRedisMetadata`）

**forwarder 变体：**
- `x/internal/util/forwarder/sniffer_redis.go` — 新增（`HandleRedis` + `resolveRedisNode`）

**recorder：**
- `x/recorder/recorder.go` — `RedisRecorderObject` + `HandlerRecorderObject.Redis` 字段

**handler 分派（5 处，仅 Redis case）：**
- `x/handler/forward/local/sniffing.go`
- `x/handler/forward/remote/sniffing.go`
- `x/handler/sni/sniffing.go`
- `x/handler/http/connect.go`
- `x/handler/relay/connect.go`

**文档：** `play/` 或 `docs/` 增加 Redis sniffing 示例（可选）

> 跨 repo 联动（gost-plugins/recorder、inspector）仅标注，不在本计划执行范围，见「跨 repo 联动」小节。

### 第二阶段（PostgreSQL）
- `x/internal/util/sniffing/sniff.go` — Tier-1 PG 分支（byte0=0x00 → Peek(8)）
- `x/internal/util/sniffing/sniffer_postgres.go` — 新增（`HandlePostgres` + `ParsePostgresMetadata`）
- `x/internal/util/forwarder/sniffer_postgres.go` — 新增（`HandlePostgres` + `resolvePostgresNode`）
- `x/recorder/recorder.go` — `PostgresRecorderObject` + `HandlerRecorderObject.Postgres` 字段
- 5 处 handler 分派，加 Postgres case

> 跨 repo 联动（gost-plugins/recorder、inspector）仅标注，不在本计划执行范围，见「跨 repo 联动」小节。

---

## 范围之外（明确不做）

- MySQL / SMTP：服务端先发包，当前 preread 架构无法检测。
- Mongo/Memcached/OpenVPN/RTMP：可作为后续独立 enh，本期不做。
- TLS 内层解密后的 Redis/PG 明文嗅探（MITM 仅 HTTP）：不做。
- SSH 嗅探 handler：已讨论，价值低（无路由元数据），本期不接（Sniff() 已有 ProtoSSH 检测）。
- auto handler 的 Redis/PG 接入：不做（auto 语义是 SOCKS/TLS/HTTP 三元分发，且 auto 路径缺乏 `HandleRedis`/`HandlePostgres` 需要的 sniffing Sniffer）。
