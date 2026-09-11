# HTTP Response Cache for Reverse Proxy (Port Forwarding with HTTP Sniffer)

## Context

为 GOST 的反向代理（local port forward + HTTP sniffer）增加类似 nginx `proxy_cache` 最简子集的缓存功能。

GOST 目前做 HTTP 转发时不缓存任何响应——每个请求都完整转发到 upstream。对于可缓存的静态资源或 API 响应，这会浪费 upstream 带宽和延迟。

## Requirements

- **缓存粒度**：Method + Host + URI 作为缓存键（`GET example.com/api/users`）
- **过期策略**：TTL（可配置），忽略标准 HTTP Cache-Control 语义
- **存储**：纯内存，进程重启丢失
- **配置位置**：chain node 级别，与现有 `httpSettings`（rewriteURL, requestHeader 等）同级
- **范围**：最简可用，不实现 RFC 7234 完整语义

## Design

### Architecture

在 `httpRoundTrip` 的请求-响应周期中插入缓存层：

```
客户端请求 → HandleHTTP → httpRoundTrip
                            ├─ 缓存命中 (未过期) → 直接写回客户端
                            └─ 缓存未命中/已过期 → dial upstream → tee writer 同时写客户端和捕获字节 → 写完后将捕获的完整响应存入缓存
```

**缓存键**：`Method + " " + Host + " " + URI`，例如 `GET example.com/api/users`。不同 Host 的相同 URI 可能返回不同内容，Host 不可省略。

**只缓存幂等请求**：GET/HEAD 缓存，POST/PATCH/DELETE 等非幂等方法不缓存。

**缓存实例**：存储在 `*Sniffer` 结构体上，首次遇到启用缓存的 node 时惰性初始化。一个 Sniffer 服务于一个 service，这是合理的缓存共享范围。

### Files to modify

#### 1. `core/chain/node.go` — 新增配置结构体

在 `HTTPNodeSettings` 中增加 `Cache` 字段：

```go
type HTTPNodeSettings struct {
    // ... existing fields ...
    Cache *HTTPCacheSettings `json:"cache,omitempty" yaml:"cache,omitempty"`
}

type HTTPCacheSettings struct {
    Enabled      bool   `json:"enabled" yaml:"enabled"`
    TTL          time.Duration `json:"ttl" yaml:"ttl"`          // 缓存过期时间，默认 60s
    MaxEntries   int    `json:"maxEntries" yaml:"maxEntries"`   // 最大条目数，默认 1000
    MaxBodyBytes int    `json:"maxBodyBytes" yaml:"maxBodyBytes"` // 缓存的最大响应体大小，默认 1MB
}
```

#### 2. `x/config/parsing/node/parse.go` — 配置解析

在 `parseHTTP` 函数中解析缓存配置到 `httpSettings.Cache`。

YAML 配置示例：
```yaml
nodes:
- name: cache-node
  addr: upstream:8080
  http:
    cache:
      enabled: true
      ttl: 300s
      maxEntries: 500
      maxBodyBytes: 2097152  # 2MB
```

#### 3. `x/internal/util/forwarder/cache.go` — 新增缓存实现

```go
type httpCache struct {
    mu         sync.RWMutex
    entries    map[string]*cacheEntry
    maxEntries int
}

type cacheEntry struct {
    data      []byte    // resp.Write() 输出的完整 HTTP 响应（status line + headers + body）
    expiresAt time.Time
}
```

- `get(key string) (*http.Response, error)` — 检查过期，返回克隆的响应
- `set(key string, data []byte, ttl time.Duration)` — 按 `[]byte` 存（已经 tee 捕获好了），满时淘汰最老条目
- `delete(key string)`
- `cleanup()` — 后台 goroutine 定期清理过期条目
- `teeWriter(w io.Writer, maxBytes int) *cacheTeeWriter` — 条件化 tee writer：同时写客户端和捕获字节，超过 `maxBytes` 时停止捕获（丢弃整个缓冲），避免为大响应体浪费内存

序列化/反序列化使用 `net/http` 标准 `resp.Write` / `http.ReadResponse`。

#### 4. `x/internal/util/forwarder/sniffer_http.go` — 集成缓存

在 `httpRoundTrip` 中两处插入：

- **函数开头**（~第 320 行，`dial` 之前）：检查 `node.HTTP.Cache.Enabled`，若启用且方法为 GET/HEAD，查缓存。命中则 `cachedResp.Write(rw)` → 直接返回。此时 `cc` 为 nil，`defer cc.Close()` 需 guard nil。

- **响应写入处**（替换 ~第 566-571 行的 `resp.Write(rw)`）：若缓存启用且响应满足条件（2xx/3xx，体大小未超标），用 `cache.teeWriter` 包装 `rw`，使得 `resp.Write(tee)` 同时写入客户端和捕获字节。写完后若捕获成功则同步存入缓存。不满足条件则直接用原来的 `resp.Write(rw)`。

**Singleflight 优化**：使用 `golang.org/x/sync/singleflight`（已在依赖中）防止同一缓存键的并发 miss 都去打 upstream——只有第一个请求真正转发，其他等待共享结果。

**缓存命中时的 Date 头**：回放的响应保留捕获时的原始 `Date`。这与 nginx `proxy_cache` 默认行为一致，不算 bug。如需覆盖可后续加配置项。

### Safety guards

| 机制 | 说明 |
|------|------|
| `maxEntries` | 条目数上限，超过则淘汰最老条目 |
| `maxBodyBytes` | 单响应体上限，超过不缓存 |
| 只缓存 GET/HEAD | POST/PATCH 等非幂等方法不缓存 |
| 只缓存 2xx/3xx | 不缓存错误响应 |
| 过期条目后台清理 | 独立 goroutine，60s 默认间隔 |
| `singleflight` | 防止 thundering herd |

### What is NOT included (and why)

- **磁盘持久化** — 用户选择纯内存
- **Cache-Control/ETag/条件请求** — 最简方案，不实现 RFC 7234
- **Vary 头处理** — 最简方案忽略
- **PURGE/缓存清理 API** — 后续需要再加
- **缓存统计/指标** — 后续集成到 metrics 体系
- **分布式缓存（Redis 等）** — 单进程场景不需要

## Complexity and Effort

| 维度 | 评估 |
|------|------|
| 新增文件 | 1 个（`cache.go` ~120 行） |
| 修改文件 | 3 个（`node.go` +5 行, `parse.go` +10 行, `sniffer_http.go` +20 行） |
| 总代码量 | ~155 行 |
| 新依赖 | 0（所有依赖已在 go.mod 中） |
| 复杂度 | 低 |
| 估时 | 半天开发 + 半天测试 |

## Risk Assessment

| 风险 | 等级 | 缓解 |
|------|------|------|
| 内存膨胀 | 中 | `maxEntries` + 最老淘汰 |
| 缓存错误响应 | 低 | 只缓存 2xx/3xx |
| 并发 miss 惊群 | 低 | `singleflight` 合并并发请求 |
| 大响应体占内存 | 中 | `maxBodyBytes` 上限 |
| 与 rewrite 管道交互 | 低 | 缓存在 rewrite **之后**存储，在 rewrite **之前**返回——即缓存的是最终改写后的响应 |

## Verification

1. **单元测试**：`cache_test.go` — 测试 set/get/expire/eviction/cleanup
2. **集成测试**：修改 `sniffer_test.go` — 模拟 upstream 返回可缓存响应，验证第二次请求命中缓存
3. **手动验证**：
   ```bash
   # 启动 gost 作为反向代理，配置缓存
   go run ./cmd/gost/... -L "tcp://:8080" -F "tcp://upstream:9090?http.cache.enabled=true&http.cache.ttl=30s"
   # 两次相同的请求应该都在日志中显示 first request → upstream, second → cache hit
   ```
