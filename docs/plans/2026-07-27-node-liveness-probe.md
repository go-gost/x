# Node-Level Liveness Probe

## Context

GOST 当前依赖**被动失败检测**：节点仅在真实连接失败时被标记（`FailFilter` 在 `failTimeout`
后让其回到候选池），没有主动健康检查、没有时延测量，因此无法做基于健康/时延的路由决策。

本计划实现 **node 级** 主动探测。选择 node 级而非 chain 级，原因：

- chain 级探测（`x/docs/plans/chain-liveness-probe.md`）用 `chain.Route(addr).Dial(addr)`，
  而 `Route()` 会按每个 hop 的 selector（random/round-robin）**任选节点**，每次探测 tick 可能
  走不同 node，结果（成功/时延）被盖到整条 chain 唯一的 `Marker` 上 → 假健康 + 假死亡，
  **结果不准确**。
- node 级探测用**节点自身的 `Transport`** 钉死到该 node（`Dial(node.Addr)` → `Connect(probeAddr)`），
  每个 node 独立记录健康与时延，`FailFilter` 在同 hop 内精准剔除死 node，
  `LowestLatencyStrategy`/`LatencyFilter` 在同 hop 内选最优 node。

> 结论：`chain-liveness-probe.md` 应据此**改写**（probe 下沉到 node，chain 健康由 node 聚合
> 推导），不可照原样执行。本计划是 node 级版本的详细实现。

## Design Overview

```
YAML → ParseNode → xchain.StartNodeProbe → goroutine (per node)
                                      |
                                 ticker loop (interval)
                                      |
                tr.Dial(ctx, node.Addr) → Handshake → tr.Connect(ctx, conn, network, probeAddr)
                                      |
                   success → node.Marker().Reset()  +  node.SetProbeResult(ok, latency)
                   failure → node.Marker().Mark()    +  node.SetProbeResult(fail)
                                      |
        FailFilter(hop) 自动跳过 marker 死亡的 node  ← 零 selector 改动
        lowestlatency / maxLatency 在同 hop 内按时延选 node
```

每个 `Node` 拥有自己的探测 goroutine，结果写入 `node.probeResult`（`atomic.Value`）与
`node.marker`（现有失败标记）。`Node` 实现 `chain.ProbeResultReader`，使泛型
`LowestLatencyStrategy[T]`/`LatencyFilter[T]` 对 `*chain.Node` 与 `chain.Chainer` 同时生效。

**准确性范围（Phase 1）**：探测用 node 自身 transport 直连 node，对**首跳 / 单跳节点**
（客户端可直接拨达的代理）准确有效。深跳节点（需经上游 hop 才能到达）的探测需 pin 住上游路径，
列为后续工作（见文末）。

## Config Schema

```yaml
chains:
- name: chain-1
  hops:
  - name: hop-1
    selector:
      strategy: lowestlatency     # 同 hop 内选最低时延 node
      maxLatency: 500ms            # 超阈 node 被 LatencyFilter 过滤
    nodes:
    - name: proxy1
      addr: 10.0.0.1:1080
      connector: { type: socks5 }
      dialer: { type: tcp }
      probe:                       # node 级探测
        type: tcp                  # "tcp" 或 "http"
        addr: 8.8.8.8:53           # 探测目标（经此 node 穿透）
        interval: 30s              # 探测间隔（默认 30s）
        timeout: 10s               # 单次探测超时（默认 10s）
        maxFails: 2                # 连续失败几次标记死亡（默认 1）
    - name: proxy2
      addr: 10.0.0.2:1080
      probe:
        type: http
        addr: httpbin.org:80
        httpPath: /get
        expectedStatus: 200
        interval: 60s
        timeout: 15s
```

## Implementation Plan

### Step 1: `core/chain/probe.go`（NEW）

与 chain 计划同名的类型，供 node 与 chain 共用：

```go
package chain

import "time"

type ProbeType string

const (
    ProbeTypeTCP  ProbeType = "tcp"
    ProbeTypeHTTP ProbeType = "http"
)

type ProbeConfig struct {
    Type           ProbeType
    Addr           string        // 探测目标（经 node 穿透）
    Interval       time.Duration
    Timeout        time.Duration
    MaxFails       int
    HTTPPath       string
    HTTPHost       string
    HTTPHeaders    map[string]string
    ExpectedStatus int
}

type ProbeResult struct {
    Success   bool
    Latency   time.Duration
    Error     string
    Timestamp time.Time
}

// ProbeResultReader 由 Node 与 Chain 共同实现，供泛型时延策略/过滤器使用。
type ProbeResultReader interface {
    ProbeResult() *ProbeResult
}
```

### Step 2: `core/chain/node.go`（MODIFY）

`Node` 增加探测状态字段与小访问器（与既有 `marker selector.Marker` 同风格；goroutine 逻辑放 `x/chain`，
core 只持有状态）。`ProbeResult()` 使 `Node` 实现 `ProbeResultReader`。

```go
import (
    "context"
    "sync/atomic"
)

type Node struct {
    Name        string
    Addr        string
    marker      selector.Marker
    probeResult atomic.Value       // NEW
    probeCancel context.CancelFunc // NEW
    options     NodeOptions
}

// ProbeResult 实现 chain.ProbeResultReader。
func (node *Node) ProbeResult() *ProbeResult {
    if v := node.probeResult.Load(); v != nil {
        return v.(*ProbeResult)
    }
    return nil
}

func (node *Node) SetProbeResult(r *ProbeResult) { node.probeResult.Store(r) }

func (node *Node) SetProbeCancel(c context.CancelFunc) { node.probeCancel = c }

// Close 停止本 node 的探测 goroutine（被 hop/chain Close 级联调用）。
func (node *Node) Close() error {
    if node.probeCancel != nil {
        node.probeCancel()
    }
    return nil
}
```

### Step 3: `x/chain/node.go`（NEW）— node 探测 goroutine

实现逻辑放 `x`（core 不含实现）。`StartNodeProbe` 由 `ParseNode` 调用：

```go
package chain

import (
    "context"
    "time"

    "github.com/go-gost/core/chain"
    "github.com/go-gost/x/internal/probe"
    "github.com/go-gost/core/logger"
)

func StartNodeProbe(node *chain.Node, cfg *chain.ProbeConfig, log logger.Logger) {
    if cfg == nil || cfg.Addr == "" {
        return
    }
    ctx, cancel := context.WithCancel(context.Background())
    node.SetProbeCancel(cancel)
    go runNodeProbe(ctx, node, cfg, log)
}

func runNodeProbe(ctx context.Context, node *chain.Node, cfg *chain.ProbeConfig, log logger.Logger) {
    interval := cfg.Interval
    if interval <= 0 {
        interval = 30 * time.Second
    }
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    probeNode(node, cfg, log) // 首次立即探测
    for {
        select {
        case <-ticker.C:
            probeNode(node, cfg, log)
        case <-ctx.Done():
            return
        }
    }
}

func probeNode(node *chain.Node, cfg *chain.ProbeConfig, log logger.Logger) {
    timeout := cfg.Timeout
    if timeout <= 0 {
        timeout = 10 * time.Second
    }
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    start := time.Now()
    tr := node.Options().Transport
    conn, err := tr.Dial(ctx, node.Addr) // 直连本 node
    if err == nil {
        if hc, err2 := tr.Handshake(ctx, conn); err2 == nil {
            conn = hc
        } else {
            conn.Close()
            err = err2
        }
    }
    latency := time.Since(start)

    result := &chain.ProbeResult{Timestamp: time.Now(), Latency: latency}
    if err != nil {
        result.Success = false
        result.Error = err.Error()
        node.Marker().Mark()
    } else {
        defer conn.Close()
        if cfg.Type == chain.ProbeTypeHTTP {
            if e := probe.NewHTTPProber(cfg).Probe(conn, cfg.Addr); e != nil {
                result.Success = false
                result.Error = e.Error()
                node.Marker().Mark()
            } else {
                result.Success = true
                node.Marker().Reset()
            }
        } else {
            result.Success = true
            node.Marker().Reset()
        }
    }
    node.SetProbeResult(result)
    log.Debugf("node probe %s: success=%v latency=%v", node.Name, result.Success, latency)
}
```

**要点**：探测走 `node.Options().Transport`（即 `ParseNode` 为该 node 构造的 transporter），
`Dial(node.Addr)` 接通本 node、`Connect` 穿透到 `probeAddr`，因此结果只反映这一个 node，
不会被 hop selector 漂走到其他 node。TCP 探测只验证隧道可达；HTTP 探测用 `HTTPProber` 校验状态码。

### Step 4: `x/internal/probe/probe.go`（NEW）— HTTPProber

复用 chain 计划的 HTTP 探测器（TCP 探测在 Step 3 内联处理，无需额外包）：

```go
package probe

type HTTPProber struct {
    Path           string
    Host           string
    Headers        map[string]string
    ExpectedStatus int
}

// Probe 在 conn 上发送 GET <path> 并校验状态码。
func (p *HTTPProber) Probe(conn net.Conn, addr string) error
```

实现：构造 `GET <path> HTTP/1.1\r\nHost: <host>\r\n...` 经 `conn` 发送，读取响应，校验
`status == ExpectedStatus`（默认 200），任何 I/O 错误或状态码不符返回 error。

### Step 5: `core/chain/probe.go` 的配置类型已在 Step 1 定义；`x/config/config.go`（MODIFY）

```go
// 新增共享类型
type ProbeConfig struct {
    Type           string            `json:"type"`
    Addr           string            `json:"addr,omitempty"`
    Interval       time.Duration     `json:"interval"`
    Timeout        time.Duration     `json:"timeout"`
    MaxFails       int               `json:"maxFails"`
    HTTPPath       string            `json:"httpPath,omitempty"`
    HTTPHost       string            `json:"httpHost,omitempty"`
    HTTPHeaders    map[string]string `json:"httpHeaders,omitempty"`
    ExpectedStatus int               `json:"expectedStatus,omitempty"`
}

// NodeConfig 增加 probe
type NodeConfig struct {
    // ... 现有字段不变 ...
    Probe *ProbeConfig `yaml:",omitempty" json:"probe,omitempty"` // NEW
}

// SelectorConfig 增加 maxLatency
type SelectorConfig struct {
    Strategy    string        `json:"strategy"`
    MaxFails    int           `yaml:"maxFails" json:"maxFails"`
    FailTimeout time.Duration `yaml:"failTimeout" json:"failTimeout"`
    MaxLatency  time.Duration `yaml:"maxLatency,omitempty" json:"maxLatency,omitempty"` // NEW
}
```

### Step 6: `x/config/parsing/node/parse.go`（MODIFY）

在 `chain.NewNode(...)` 返回后、函数返回前，若 `cfg.Probe != nil` 启动探测：

```go
node := chain.NewNode(cfg.Name, cfg.Addr, opts...)
if cfg.Probe != nil {
    if pc := parseProbeConfig(cfg.Probe); pc != nil {
        xchain.StartNodeProbe(node, pc, nodeLogger)
    }
}
return node, nil
```

`parseProbeConfig` 同 chain 计划（addr 为空则返回 nil；interval/timeout 默认 30s/10s；
maxFails 默认 1；expectedStatus 默认 200；httpPath 默认 "/"）。

> 因 `ParseNode` 同时被 `ParseHop`（初始内联节点）与 `hop.reload`（file/redis/http 热加载）
> 调用，上述挂接**同时覆盖初始与热加载**两处。

### Step 7: `x/selector/latency.go`（NEW）— 泛型时延策略/过滤器

与 chain 计划一致，泛型约束 `chain.ProbeResultReader`，对 `*chain.Node` 与 `chain.Chainer` 都生效：

```go
package selector

import (
    "context"
    "math"
    "time"

    "github.com/go-gost/core/chain"
)

// LatencyFilter 过滤掉 ProbeResult 失败或时延超过 maxLatency 的项；
// 无探测结果的项保守放行（不过滤未 instrumentation 的项）。
func LatencyFilter[T any](maxLatency time.Duration) selector.Filter[T] {
    return selector.FilterFunc[T](func(ctx context.Context, vs ...T) []T {
        var out []T
        for _, v := range vs {
            if reader, ok := any(v).(chain.ProbeResultReader); ok {
                r := reader.ProbeResult()
                if r != nil && (!r.Success || (maxLatency > 0 && r.Latency > maxLatency)) {
                    continue
                }
            }
            out = append(out, v)
        }
        return out
    })
}

// LowestLatencyStrategy 选 ProbeResult 时延最低的项；无结果者排最后。
func LowestLatencyStrategy[T any]() selector.Strategy[T] {
    return selector.StrategyFunc[T](func(ctx context.Context, vs ...T) (v T) {
        var best *chain.ProbeResult
        for _, item := range vs {
            reader, ok := any(item).(chain.ProbeResultReader)
            if !ok {
                if !isNil(v) { continue }
                v = item
                continue
            }
            r := reader.ProbeResult()
            if r == nil || !r.Success {
                continue
            }
            if best == nil || r.Latency < best.Latency {
                best = r
                v = item
            }
        }
        return v
    })
}
```

> 注：`selector.FilterFunc`/`selector.StrategyFunc` 若 core/selector 未提供，则在 `x/selector`
> 内用闭包实现 `selector.Filter[T]`/`selector.Strategy[T]` 接口即可（与现有
> `defaultSelector` 同构）。

### Step 8: `x/config/parsing/selector/parse.go`（MODIFY）

`ParseNodeSelector` 增加 `lowestlatency`/`lowest`/`ll` 策略，并在 `maxLatency > 0` 时追加
`LatencyFilter[*chain.Node]`（**node 级**）：

```go
case "lowestlatency", "lowest", "ll":
    strategy = xs.LowestLatencyStrategy[*chain.Node]()

filters := []selector.Filter[*chain.Node]{
    xs.FailFilter[*chain.Node](cfg.MaxFails, cfg.FailTimeout),
    xs.BackupFilter[*chain.Node](),
}
if cfg.MaxLatency > 0 {
    filters = append(filters, xs.LatencyFilter[*chain.Node](cfg.MaxLatency))
}
return xs.NewSelector(strategy, filters...)
```

（`ParseChainSelector` 暂不动；chain 级 lowestlatency 留待 Phase 2 聚合推导。）

### Step 9: 生命周期级联（关键）

**`x/hop/hop.go`** — 扩展 `chainHop.Close()`，级联停止本 hop 所有 node 的探测：

```go
func (p *chainHop) Close() error {
    p.cancelFunc()
    for _, n := range p.Nodes() {
        if n != nil {
            n.Close() // 停止 node 探测 goroutine
        }
    }
    // ... 现有 loader 关闭 ...
    return nil
}
```

**`x/chain/chain.go`** — 新增 `Chain.Close()`（`io.Closer`），级联到各 hop：

```go
func (c *Chain) Close() error {
    for _, h := range c.hops {
        if closer, ok := h.(io.Closer); ok {
            closer.Close()
        }
    }
    return nil
}
```

registry `Unregister(chain)` 会对实现 `io.Closer` 的 chain 调 `Close()`（见
`x/registry/registry.go:87`），因此 **config reload 自动停止所有 node 探测 goroutine**，无泄漏。

## File Change Summary

| 文件 | 变更 |
|------|------|
| `core/chain/probe.go` | **NEW** — `ProbeType`/`ProbeConfig`/`ProbeResult`/`ProbeResultReader` |
| `core/chain/node.go` | 加 `probeResult`/`probeCancel` 字段 + `ProbeResult()`/`SetProbeResult()`/`SetProbeCancel()`/`Close()` |
| `x/chain/node.go` | **NEW** — `StartNodeProbe`/`runNodeProbe`/`probeNode` |
| `x/internal/probe/probe.go` | **NEW** — `HTTPProber` |
| `x/config/config.go` | 加 `ProbeConfig`；`NodeConfig` 加 `Probe`；`SelectorConfig` 加 `MaxLatency` |
| `x/config/parsing/node/parse.go` | 末尾 `node.SetProbe`→`StartNodeProbe`；加 `parseProbeConfig` |
| `x/selector/latency.go` | **NEW** — `LatencyFilter[T]`/`LowestLatencyStrategy[T]` |
| `x/config/parsing/selector/parse.go` | `ParseNodeSelector` 加 `lowestlatency` + `LatencyFilter` |
| `x/hop/hop.go` | `chainHop.Close()` 级联 `node.Close()` |
| `x/chain/chain.go` | 新增 `Chain.Close()` 级联 hop |

**总计：4 个新文件，6 个修改文件。不动 registry/loader 的清理机制。**

## 向后兼容

- 无 `probe` 字段 → node 不启探测 goroutine，`Close()` 对 nil `probeCancel` 为 no-op。
- `FailFilter` 已消费 `node.Marker()`，probe 仅更新该 marker → 现有 selector 行为不变。
- 现有 `round`/`random`/`fifo`/`hash` 策略不变；`lowestlatency` 为新增可选策略。
- 现有 YAML 全部有效。

## 已知限制 / 后续

- **深跳节点探测**：Phase 1 仅对首跳/单跳节点（客户端可直接拨达）准确。深跳节点需先穿透上游
  hop 才能到达，其探测要 pin 住上游路径（构造仅含该路径的 route），列为 Phase 2。
- **热加载节点 churn**：`hop.reload` 追加新节点会启动新探测；被移除的旧节点探测在「整链 unregister」
  时才经 `Chain.Close()` 级联停止。file/redis/http 增量热加载下的旧节点探测清理可后续细化
  （reload 时对离场节点调 `Close()`）。
- **chain 级健康**：Phase 2 由 node `ProbeResult` 聚合推导（每 hop 至少一个健康 node 且取最优
  路径时延），不在 Phase 1 跑独立 chain 级探测。

## Verification

1. **Build & vet**：`cd x && go build ./... && go vet ./...`（x/ 无单测，build+vet 为验证路径）；
   `cd core && go build ./...`。
2. **Unit — node TCP probe**：起本地 TCP listener；配 node TCP probe 指向它 →
   验证 `node.ProbeResult().Success == true`；关 listener，下个 tick →
   `Success == false` 且 `node.Marker().Count() > 0`；`FailFilter` 不再选该 node。
3. **Unit — node HTTP probe**：本地 HTTP server `/health` 返回 200/500 各验证一次。
4. **Unit — Close 停 goroutine**：`node.Close()` 后无更多 marker / probeResult 更新。
5. **Unit — LowestLatencyStrategy on nodes**：mock 不同 node 时延，验证选最快；
   `LatencyFilter` 验证超阈被滤。
6. **Integration — hop failover**：hop 内一健康一死 node（`strategy: lowestlatency`），
   验证死 node 被剔除、恢复后重新入选。
7. **手动 e2e**：`play/` 新增多 node hop 配置（`strategy: lowestlatency` + `maxLatency`），
   `cd gost && go run ./cmd/gost/... -C play/xxx.yml` 观察节点分布与日志。
