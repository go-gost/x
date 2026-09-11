# Router Handler 重构设计

## 概述

对 `x/handler/router/` 包进行重构和全面单元测试。该包实现了一个 UDP/TUN 路由处理器，通过 Relay 协议的 `CmdAssociate` 接收客户端连接，将虚拟 IP 数据包路由到远程连接器。

**原则**：仅重构现有代码结构 + 补全测试，不新增功能，不改变外部行为。

## 当前状态

- 5 个源文件，1056 行代码，零测试
- 核心数据结构：`Router`、`Connector`、`ConnectorPool`
- 核心处理逻辑：`handleAssociate`（UDP 关联）、`handlePacket`（IP 包路由）、`handleEntrypoint`（UDP 入口）
- 生命周期：`Init` → `Handle` → `Close`

## 重构后文件布局

```
handler/router/
│
├── router.go           # Router / Connector / ConnectorPool — 纯数据结构
├── handler.go          # routerHandler 结构体, NewHandler, Init, Handle, Close
├── associate.go        # handleAssociate 主流程 + handlePacket + getRoute + getAddrforRoute + sdRenew
├── entrypoint.go       # handleEntrypoint UDP 入口
├── metadata.go         # metadata struct, parseMetadata, 常量
├── conn.go             # packetConn（带长度前缀的 Read/Write）+ lockWriter
├── observe.go          # observeStats + checkRateLimit
│
├── helpers_test.go     # 所有测试辅助类型
├── router_test.go      # Router / Connector / ConnectorPool 测试
├── handler_test.go     # NewHandler, Init, Handle, Close 测试
├── associate_test.go   # handleAssociate + handlePacket + getRoute + getAddrforRoute + sdRenew 测试
├── entrypoint_test.go  # handleEntrypoint 测试
├── metadata_test.go    # parseMetadata 测试
├── conn_test.go        # packetConn + lockWriter 测试
└── observe_test.go     # observeStats + checkRateLimit 测试
```

### 提取操作（纯移动，不修改逻辑）

| 操作 | 源文件 | 目标文件 | 内容 |
|------|--------|----------|------|
| 提取 | `associate.go` | `conn.go` | `packetConn`、`lockWriter`、`LockWriter` |
| 提取 | `handler.go` | `observe.go` | `observeStats`、`checkRateLimit` |

### 需修复的 Bug

1. **`router.go:DelConnector` — 匹配后缺少 `break`**：找到匹配的 connector 后未跳出循环，可能误删后续元素

## 测试策略

### Mock 辅助类型（`helpers_test.go`）

| 类型 | 实现 | 用途 |
|------|------|------|
| `testLogger` | 所有方法空实现 | 测试日志 |
| `testMD` | 包装 map → Metadata | 构建 metadata |
| `fakeConn` | bytes.Buffer 后端的 net.Conn | Handler 输入 |
| `pipeConn` | io.Pipe 后端的双向 net.Conn | 集成测试双向通信 |
| `fakePacketConn` | channel 后端的 net.PacketConn | Entrypoint 测试 |
| `fakeObserver` | channel 后端的 observer.Observer | observeStats 测试 |
| `mockAuther` | 函数注入的 auth.Authenticator | 认证测试 |
| `mockRateLimiterContainer` | 函数注入的 rate.RateLimiter | checkRateLimit 测试 |
| `mockTrafficLimiter` | 空实现的 traffic.TrafficLimiter | Init 测试 |
| `mockRouter` | 函数注入的 router.Router | getRoute 测试 |
| `mockSD` | 函数注入的 sd.SD | SD 注册/查找测试 |
| `mockIngress` | 函数注入的 ingress.Ingress | handleAssociate 路由验证 |
| `buildRelayAssociateRequest` | 序列化 relay.Request | 构造测试输入 |
| `readRelayResponse` | 反序列化 relay.Response | 验证输出 |

### 测试文件

#### `metadata_test.go` — parseMetadata 全面测试

- 空 metadata
- 仅 readTimeout
- bufferSize 默认值 / 自定义值
- entryPoint 设置
- ingress 注册查找
- sd / sd.cache.expiration / sd.renewInterval 默认值
- router / router.cache / router.cache.expiration 默认值
- observePeriod 默认值 / 最小值限制
- observer.resetTraffic
- limiter.refreshInterval / limiter.cleanupInterval

#### `router_test.go` — Router / Connector / ConnectorPool

**Connector:**
- NewConnector（nil opts、完整 opts）
- ID / Writer / Close（nil-safe）
- Close 重复调用

**Router:**
- NewRouter
- AddConnector（nil 跳过、多元素添加）
- GetConnector（单元素、多元素、权重选择、MaxWeight 优先级、空 host）
- DelConnector（精确删除、不存在 host、不存在 cid、匹配后 break 验证）
- Close（重复调用安全、connector 清理）

**ConnectorPool:**
- NewConnectorPool
- Add（新 Router 创建、已有 Router 追加）
- Get（nil-safe、存在/不存在 rid、存在/不存在 host）
- Del（nil-safe、精确删除）
- Close（nil-safe、重复调用）

**parseRouterID:**
- 空字符串
- 有效 UUID
- 无效 UUID

#### `conn_test.go` — packetConn + lockWriter

**packetConn:**
- Read 正常（2 字节长度前缀 + 数据）
- Read 空数据（长度 0）
- Read 缓冲区小于数据（截断）
- Write 正常
- Write 超过 MaxUint16（错误）
- Write 后 Read 往返

**lockWriter:**
- Write 正常
- 并发写入安全性
- Close（io.Closer 包装/非 Closer 包装）
- Close 重复调用

#### `observe_test.go` — observeStats + checkRateLimit

**checkRateLimit:**
- RateLimiter 为 nil（返回 true）
- Limiter Allow 返回 true
- Limiter Allow 返回 false

**observeStats:**
- Observer 为 nil（立即返回）
- 正常周期事件发送
- Observer.Observe 返回 error（重试机制）
- 重试成功后清空 events
- context cancel 退出
- observerResetTraffic 设置

#### `handler_test.go` — NewHandler, Init, Handle, Close

**NewHandler:**
- 最小构造
- 带 Options 构造

**Init:**
- 最小 Init（验证 id、pool、cancel 初始化）
- 带 Observer（验证 stats 初始化、goroutine 启动）
- 带 Limiter
- entrypoint Init 错误
- parseMetadata 错误

**Handle:**
- 请求读取错误
- Bad Version
- Unknown Command
- Rate Limit 拒绝
- 认证成功/失败
- 正常 Associate 流程（发送 relay request → 读取 response → 发送 packet）
- 多 Feature 请求（auth + addr + tunnel + network）

**Close:**
- 正常关闭
- 重复关闭
- entrypoint 未初始化

#### `associate_test.go` — handleAssociate + handlePacket + getRoute + getAddrforRoute + sdRenew

**handleAssociate:**
- 正常关联流程（ingress 验证通过 → connector 注册 → packet 循环）
- ingress 验证失败（host 不匹配 → StatusHostUnreachable）
- ingress 为 nil（跳过验证）
- connectorID 生成
- SD 注册/注销
- connector 在 defer 中清理

**handlePacket:**
- IPv4 包解析 + 路由查找 + connector 转发
- IPv6 包解析 + 路由查找 + connector 转发
- 未知包类型（错误返回）
- 无路由（no route to host 错误）
- connector 不存在时通过 entrypoint 转发
- SD 查找 + entrypoint 写入

**getRoute:**
- 缓存命中（未过期）
- 缓存未命中 → registry 查找
- registry 未找到 → fallback router
- 缓存未启用

**getAddrforRoute:**
- SD 缓存命中
- SD 缓存未命中 → 查找
- 自身节点跳过
- SD 为 nil

**sdRenew:**
- 正常 tick 续期
- context cancel 退出

#### `entrypoint_test.go` — handleEntrypoint

- 正常 relay request 转发到 connector
- 非 Associate cmd 跳过
- ReadFrom error 返回
- 空 connector（无匹配 connector 时忽略）
- connector Writer 写入错误（仅日志记录）

## 测试基础设施

- 使用 `testing/quick` 或手动构造 relay 协议字节流
- 使用 `io.Pipe` 模拟双向网络连接
- 使用 channel 同步异步 goroutine（observeStats、sdRenew）
- 所有测试运行 `go test -race` 验证无竞态