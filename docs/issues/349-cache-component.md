# Issue #349: 通用 Cache 组件设计

## Context

Issue [#349](https://github.com/go-gost/gost/issues/349) 请求 HTTP 代理缓存层。用户要求先聚焦 cache 组件本身，设计要通用——不仅用于 HTTP，也要能统一替换现有的 DNS、Router、Traffic Limiter、TLS 等模块中的 ad-hoc 缓存。

## 现状：6 处独立缓存实现

| 位置 | 底层库 | Key | Value | TTL 模式 | 淘汰 | 最大容量 |
|------|--------|-----|-------|----------|------|----------|
| `x/internal/util/cache` | 自实现 | `string` | `interface{}` | 硬过期 | 无 | 无 |
| `x/internal/util/resolver` (DNS) | 自实现 | `CacheKey(string)` | `*dns.Msg` | 硬过期 + serve-stale | 最旧(O(n)) | 可选 |
| `x/limiter/traffic/cache` | #1 之上 | `string` | `traffic.Limiter` | 硬过期 + 刷新时滑动 | 无 | 无 |
| `x/limiter/traffic` | patrickmn/go-cache | `string` | `traffic.Limiter` | **滑动**(Get时重置) | 后台清理 | 无 |
| `x/internal/util/tls` | patrickmn/go-cache | `string` | `*x509.Certificate` | 硬过期(1周) | 后台清理 | 无 |
| `x/handler/router` | #1 之上 | `string` | `net.Addr` / `*Route` | 硬过期(1s) | 无 | 无 |

**问题**: 三种底层实现（自实现 ×2 + patrickmn/go-cache），功能重叠但接口不兼容，无通用配置入口。

---

## Core Interface

### `core/cache/cache.go` (新文件)

```go
package cache

var ErrNotFound = errors.New("cache: key not found")

// Entry 缓存条目
type Entry struct {
    Data       []byte
    Expiration time.Time  // zero = 永不过期
}

func (e *Entry) Expired() bool
func (e *Entry) TTL() time.Duration  // 剩余 TTL，负数=已过期，-1=永不过期

// SetOptions 写入选项
type SetOptions struct {
    TTL time.Duration  // 逐条 TTL
}
type SetOption func(*SetOptions)
func WithTTL(d time.Duration) SetOption

// Cache 通用 KV 缓存接口
// 实现必须并发安全
type Cache interface {
    Get(ctx context.Context, key string) (*Entry, error)
    Set(ctx context.Context, key string, data []byte, opts ...SetOption) error
    Delete(ctx context.Context, key string) error
    Has(ctx context.Context, key string) bool
    Clear(ctx context.Context) error
    Len(ctx context.Context) int
    RefreshTTL(ctx context.Context, key string, ttl time.Duration) error
}
```

**设计决策**:
- Key 固定为 `string`，Value 固定为 `[]byte` — 与 registry 模式兼容，所有后端统一
- `Get` 返回过期条目（`ErrNotFound` 仅对不存在的 key）— 支持 DNS serve-stale
- `RefreshTTL` 显式延长过期时间 — 支持 DNS 异步刷新防重复
- 调用方自行序列化/反序列化 — Cache 不绑定任何业务类型，真正通用
- 与 `recorder.Recorder` 接口复杂度相当（都是单方法 + 选项）

### Each handler wraps with typed methods

```go
// DNS handler 中:
func dnsCacheGet(c cache.Cache, key string) (*dns.Msg, time.Duration) {
    entry, err := c.Get(ctx, key)
    if err != nil { return nil, 0 }
    msg := &dns.Msg{}
    msg.Unpack(entry.Data)
    return msg, entry.TTL()
}

// HTTP handler 中:
func httpCacheGet(c cache.Cache, key string) (*http.Response, error) { ... }
func httpCacheSet(c cache.Cache, key string, resp *http.Response, ttl time.Duration) error { ... }
```

---

## Config Structure

### `x/config/config.go` — 新增

```go
type CacheConfig struct {
    Name   string        `json:"name"`
    Memory *MemoryCache  `yaml:",omitempty" json:"memory,omitempty"`
    File   *FileCache    `yaml:",omitempty" json:"file,omitempty"`
    Redis  *RedisCache   `yaml:",omitempty" json:"redis,omitempty"`
    Plugin *PluginConfig `yaml:",omitempty" json:"plugin,omitempty"`
}

type MemoryCache struct {
    TTL             time.Duration `yaml:",omitempty" json:"ttl,omitempty"`
    MaxSize         int           `yaml:",omitempty" json:"maxSize,omitempty"`
    MaxBytes        int64         `yaml:",omitempty" json:"maxBytes,omitempty"`
    CleanupInterval time.Duration `yaml:",omitempty" json:"cleanupInterval,omitempty"`
    Eviction        string        `yaml:",omitempty" json:"eviction,omitempty"` // "oldest" | "lru"
}

type FileCache struct {
    Dir      string `json:"dir"`
    MaxBytes int64  `yaml:",omitempty" json:"maxBytes,omitempty"`
    Levels   int    `yaml:",omitempty" json:"levels,omitempty"`
}

type RedisCache struct {
    Addr      string `json:"addr"`
    DB        int    `yaml:",omitempty" json:"db,omitempty"`
    Username  string `yaml:",omitempty" json:"username,omitempty"`
    Password  string `yaml:",omitempty" json:"password,omitempty"`
    KeyPrefix string `yaml:",omitempty" json:"keyPrefix,omitempty"`
}

// 在 Config struct 加:
// Caches []*CacheConfig `yaml:",omitempty" json:"caches,omitempty"`

// 在 ServiceConfig struct 加:
// Cache string `yaml:",omitempty" json:"cache,omitempty"`
```

### YAML 示例

```yaml
caches:
- name: cache-0
  memory:
    ttl: 60m
    maxSize: 10000
    maxBytes: 268435456   # 256MB
    cleanupInterval: 5m
    eviction: lru

services:
- name: service-0
  addr: ":8080"
  handler:
    type: http
  cache: cache-0           # 引用
  forwarder:
    nodes: [...]
```

---

## Memory Backend

### `x/cache/cache.go` — 内建实现

不依赖外部库，替代 `x/internal/util/cache/cache.go` 和 patrickmn/go-cache。

```go
type memoryCache struct {
    mu              sync.RWMutex
    entries         map[string]*entry
    defaultTTL      time.Duration
    maxSize         int
    maxBytes        int64
    currentBytes    int64
    cleanupInterval time.Duration
    evictionPolicy  EvictionPolicy
    stopCleanup     chan struct{}
    logger          logger.Logger
}

type entry struct {
    data       []byte
    expiration time.Time     // zero = 永不过期
    lastAccess time.Time     // LRU 用
}
```

**功能矩阵**:
| 特性 | 说明 |
|------|------|
| 并发安全 | `sync.RWMutex` |
| 默认 TTL | 配置项，`Set` 的 `WithTTL` 可逐条覆盖 |
| 最大条目数 | 满时按 `evictionPolicy` 淘汰（oldest / lru） |
| 最大字节数 | 满时同样淘汰 |
| 后台清理 | 可选，按 `cleanupInterval` 定期删除过期条目 |
| serve-stale | `Get` 返回过期条目，`Entry.Expired()` 让调用方判断 |
| `RefreshTTL` | 延长过期时间，用于 DNS 异步刷新模式 |
| 注册 | `init()` 注册为 `registry.CacheRegistry().Register("memory", ...)` |

**淘汰策略**: 满时 → 先清过期 → 若仍满则按策略淘汰（oldest: 按插入时间; lru: 按 `lastAccess`）

---

## 实现步骤

| Step | 文件 | 动作 | 行数 |
|------|------|------|------|
| 1 | `core/cache/cache.go` | 新建 — `Entry`, `Cache` 接口, 选项 | ~70 |
| 2 | `x/config/config.go` | 修改 — `CacheConfig` + 子结构体 + Config 字段 | ~50 |
| 3 | `x/registry/registry.go` | 修改 — `cacheReg` + `CacheRegistry()` | ~15 |
| 4 | `x/registry/cache.go` | 新建 — 热重载包装器 | ~30 |
| 5 | `x/cache/cache.go` | 新建 — memory cache 实现 | ~200 |
| 6 | `x/config/parsing/cache/parse.go` | 新建 — `ParseCache()` 后端分派 | ~50 |
| 7 | `x/config/loader/loader.go` | 修改 — cache 注册块 | ~10 |
| 8 | `x/config/parsing/service/parse.go` | 修改 — 解析 cache 引用注入 handler option | ~25 |
| 9 | `core/handler/option.go` | 修改 — `CacheOption` | ~10 |
| 10 | `gost/cmd/gost/register.go` | 修改 — blank import `x/cache` | +1 |

**总计: ~460 行，集中在 `core/cache/` 和 `x/cache/`**

### 迁移路径 (后续 Phase)

| Phase | 内容 |
|-------|------|
| **Phase 1 (本次)** | `core/cache/` 接口 + memory 后端 + config/registry 全链路 |
| **Phase 2** | DNS handler 切换到新 cache；Router handler 切换；替换 `x/internal/util/cache` |
| **Phase 3** | Traffic limiter 切换；TLS cert pool 切换；移除 patrickmn/go-cache 依赖 |
| **Phase 4** | HTTP 代理缓存集成（handler 中查缓存/存缓存） |
| **Phase 5** | File 后端；Redis 后端；Plugin 后端 |

---

## 验证

```bash
# 编译
cd x && go build ./...
cd gost && go build ./cmd/gost/...

# 单元测试
cd x && go test ./cache/... -v

# 验证 registry 集成
cd x && go vet ./...
```
