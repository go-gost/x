# Issue #853 — 无状态 UDP 包转发（`stateless` metadata）

## 背景

Issue [#853](https://github.com/go-gost/gost/issues/853)：用户需要一个类似 NGINX Stream Module 的
简单 UDP 包转发器。当前 GOST 的 `udp` 类型通过 `udp.NewListener()` 创建每客户端虚拟连接，用
`xnet.Pipe()` 做双向流拷贝——面向会话的模型与无状态"一包一响应"的语义不兼容，干扰了后端应用。

根本原因：
- `x/internal/net/udp/listener.go` 的 `udp.NewListener()` 按 remoteAddr 做 per-client 解复用，每个
  客户端一个虚拟 `net.Conn`，带接收队列 (`rc chan`)
- `x/handler/forward/local/forward.go` 的 `handleRawForwarding()` 用 `xnet.Pipe()` 做双向流拷贝，
  面向 stream 而非 datagram
- 即使 `keepalive=false`，虚拟 conn 在 TTL 内仍被 connPool 持有，同客户端快速发包可能丢失

## 方案：在现有 `udp` 代码上加 `stateless=true` metadata，辅以轻量重构

不新建服务类型，在现有 `udp` listener/handler 中增加无状态模式。通过重构 `udp.NewListener()` 消除
后台 goroutine 和 connPool 的空转开销，通过 handler 分支实现单包请求-响应路径。

### 修改的文件（6 个文件，~110 行改动，0 个新文件）

#### 1. `x/internal/net/udp/listener.go` — 核心重构（~50 行）

- **`ListenConfig`** 加 `Stateless bool` 字段
- **`NewListener()`** 加 stateless 分支：
  - 不启动 `listenLoop()` goroutine
  - 不创建 `connPool`
  - 不创建 `cqueue` 通道
- **`Accept()`** stateless 模式下直接调用 `conn.ReadFrom(buf)` 阻塞读包，读到后创建轻量
  `datagramConn` 返回（见下方），而非从 `cqueue` 通道读取
- **新增 `datagramConn` 结构体**（~15行，存于同文件）：
  ```go
  type datagramConn struct {
      pc         net.PacketConn  // 底层套接字，用于 Write 回复
      data       []byte          // 缓冲的单个数据包
      offset     int             // Read 游标
      localAddr  net.Addr
      remoteAddr net.Addr
  }
  ```
  实现 `net.Conn`：`Read` 从 data 拷贝，`Write` 调用 `pc.WriteTo(b, remoteAddr)`，
  `Close` 无操作（无状态）。无 channel、无 mutex、无池逻辑。

#### 2. `x/listener/udp/metadata.go`（~5 行）

- `metadata` 结构体加 `stateless bool` 字段
- `parseMetadata()` 中加 `l.md.stateless = mdutil.GetBool(md, "stateless")`

#### 3. `x/listener/udp/listener.go`（~2 行）

- `Init()` 中 `ListenConfig` 传入 `Stateless: l.md.stateless`

#### 4. `x/handler/forward/local/metadata.go`（~10 行）

- `metadata` 结构体加 `stateless bool`、`bufferSize int` 字段
- `parseMetadata()` 中解析

#### 5. `x/handler/forward/local/forward.go`（~40 行）

- **新增 `handleRawDatagram()` 方法**：读一个包 → 转发 → 读回复 → 写回
  ```go
  func (h *forwardHandler) handleRawDatagram(ctx context.Context, conn net.Conn, ...) error {
      // 1. hop 选择目标节点（复用现有逻辑）
      // 2. Router.Dial("udp", targetAddr)
      // 3. buf := make([]byte, h.md.bufferSize)
      //    n, _ := conn.Read(buf)
      //    cc.Write(buf[:n])
      // 4. n, _ = cc.Read(buf)        // 带 readTimeout
      //    conn.Write(buf[:n])
      // 5. cc.Close()
      //    return nil
  }
  ```
  复用 `handleRawForwarding` 的 hop 选择、Router.Dial、proxyproto、recorder、日志逻辑。

#### 6. `x/handler/forward/local/handler.go`（~5 行）

- `Handle()` 中加分支：
  ```go
  if h.md.stateless {
      return h.handleRawDatagram(ctx, conn, ro, log, network, proto)
  }
  ```

### 不改动的文件

- `gost/cmd/gost/register.go` — 不需要新空白导入
- `x/config/cmd/cmd.go` — 现有 `udp` 类型自动匹配，无需修改
- `x/internal/net/udp/pool.go` — 不动，stateless 模式根本不会调用

### 关键设计决策

- **stateless 模式下零后台 goroutine**：`listenLoop` 和 `idleCheck` 都不启动，资源开销和新建类型
  完全一致
- **`datagramConn` 极简**：只有 data + addr + offset，15 行，满足 `net.Conn` 接口但不携带任何
  session 状态
- **handler 分支点只有一个**：`Handle()` 中一行 if 决定走 datagram 路径还是 stream 路径，之后
  完全独立，互不污染
- **hop/forwarder 复用**：stateless 模式同样支持节点列表和选择器
- **`Router.Dial` 每次新建 outbound socket**：每个包一个新源端口，与 NGINX stream 行为一致；
  如需持久源端口可以后续加连接池

### 配置示例

**CLI：**
```bash
gost -L "udp://:10000/127.0.0.1:2000?stateless=true"
```

**YAML：**
```yaml
services:
- name: udp-proxy
  addr: ":10000"
  listener:
    type: udp
    metadata:
      stateless: true
  handler:
    type: udp
    metadata:
      stateless: true
  forwarder:
    nodes:
    - name: target-0
      addr: 127.0.0.1:2000
```

### 不纳入范围

- Outbound UDP socket 池化（持久源端口）
- ICMP 错误传播
- UDP 分片处理（>MTU 数据包）

## 验证

1. **Build**：`cd gost && go build ./cmd/gost/...` — 编译通过
2. **Vet**：`go vet ./x/internal/net/udp/... ./x/listener/udp/... ./x/handler/forward/local/...`
3. **手动测试**：启动 UDP echo server → 启动 gost `udp://...?stateless=true` → `nc -u` 发包验证往返正常
4. **多客户端**：两个不同端口同时发包，验证各自独立收到回复，无串扰
5. **全量编译**：`go build ./...` workspace 级别确认无回归
