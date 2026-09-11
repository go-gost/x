# GitHub 完整镜像：GOST 头重写 + URL 编码回程路由

## Context

前一轮已验证：GOST 内置 **body 重写**（`http.rewriteResponseBody`）对真实 github.com 完全生效。要做成**完整 GitHub 镜像站**，剩余缺口：

1. **响应头重写**：`Location`（302 跳回原域）、`Set-Cookie`（Domain 绑定原域 → 登录挂）、`Content-Security-Policy`（阻断镜像资源）。目前只有静态 `responseHeader` 注入（`.Set(k,v)`），无对头**值**的正则重写。全模块 grep 确认这三个头目前完全透传。
2. **请求头重写**（用户要求对称补齐）：如 `Referer`/`Origin` 指回原域、`Cookie` 域相关值、`X-Forwarded-Host` 等。
3. **URL 编码 + 回程路由**（用户提出的关键闭环问题）：body/header 里的 URL 改成镜像地址后，用户**再次请求**时如何还原"原始上游域名"来路由回正确 origin。
4. **多域路由**：GitHub 资源分散在 `*.githubusercontent.com`、`gist`、`codeload` 等。
5. **HTTPS 内可见性**：标准反向代理即可——客户端对 GOST 走 HTTP（`127.0.0.1:8080`），GOST 对上游走 HTTPS（`tls.secure: true` 校验 GitHub 证书）。**无需 MITM / 客户端信任证书**。

用户目标：完整 GitHub 镜像（JS 运行时注入的 URL 明确排除）。镜像服务可能直接用 **IP**（`127.0.0.1:8080`）而非域名，故不采用子域编码。

## 核心设计 A：URL 编码 + 回程路由（纯既有机制，零新参数）

镜像 URL = `MIRROR_HOST/<编码后的host>/<原始path>`。闭环各环节全部用既有机制实现，**不新增任何回程解码参数**：

| 环节 | 机制 | 状态 |
|------|------|------|
| 出程：origin URL → 镜像 URL（body/Location/Referer 等） | body/header 正则重写 | ✅ 已有 body 重写，本次补 header 重写 |
| 回程：按编码前缀路由到 origin node | `matcher.rule` 用**原始 path**（[sniffer_http.go:279](x/internal/util/forwarder/sniffer_http.go#L279) `PathSelectOption(req.URL.Path)`） | ✅ 纯配置 `PathPrefix`/`PathRegexp` |
| 回程：剥首段 | `http.rewriteURL`（[sniffer_http.go:476-492](x/internal/util/forwarder/sniffer_http.go#L476-L492)） | ✅ 已有，`match: '^/github\.com/'` → `replacement: '/'` |
| 回程：还原上游 Host | `http.host` **静态值**（:464-466） | ✅ 已有，`host: github.com` |

**关键洞察（用户提出，取代原 `HostFromPathPrefix` 方案）**：SNI/拨号目标钉死在 `node.Addr`（[sniffer_http.go:345](x/internal/util/forwarder/sniffer_http.go#L345)、`:360` `tlsWrapConn`），故一个 node 只能正确服务一个 origin。既然每 node 的 Host 在配置时**静态已知**，就不需要"运行时从 path 动态提取"——用 `http.host` 写死 + `rewriteURL` 剥前缀即可。原 `HostFromPathPrefix` 动态提取是死灵活性（它唯一能买的"单 node 多 host"场景在单 origin 约束下本就不该做，且 SNI 静态 + Host 动态拼不出可用 CDN 回源），**已删除**。

**编码分叉（关键约束：正则做不了 base64）**：`regexp.ReplaceAll` 只能拼固定文本，算不出 base64。所以：

- **明文 host 前缀**（选定）：`https://github.com/x` → `https://MIRROR_HOST/github.com/x`。body/header 改写全纯正则，**零插件**。github 的 origin host 只有 `[a-z0-9-]+\.(github|githubusercontent|githubassets)\.com`，path 首段绝对安全，调试直观（curl 可读）。
- **base64url 前缀**（不做）：编码需走插件（正则算不出 base64），收益仅"支持含 `:` `/` 特殊字符的任意 host"，github 用不上。见"不做"。

**头重写的传递方向（与 body URL 非对称，三类）**：

| 方向 | 作用对象 | 例子 | 传递机制 |
|------|---------|------|---------|
| **正向编码** origin→mirror | 响应 body + 响应 `Location` | body 链接、302 | 与 body 同构，回程 `http.host` + `rewriteURL` 解码 |
| **逆向解码** mirror→origin（或删） | 请求 `Referer`/`Origin`/`X-Forwarded-Host` | 客户端回传已带 mirror URL | 需解码或删除，**不可正向编码** |
| **纯删除**（浏览器态） | 响应 `Set-Cookie` Domain、CSP、HSTS | 无回程 | `match: '.*'` → `replacement: ''` |

关键：请求头是 client→上游，浏览器访问镜像时 `Referer`/`Origin` 已是 `https://127.0.0.1:8080/...`（编码态）。请求头重写只能**解码回 origin 或删除**，绝不能正向编码。GitHub 浏览场景 CSRF 靠 token 而非 Referer，故**删除最简且正确**——同时避免把 mirror host 泄漏给上游。

## 核心设计 B：头重写支持插件

`core/rewriter.Rewriter` 接口是字节式（`Rewrite(ctx, b []byte, opts ...RewriteOption) ([]byte, error)`），gRPC/HTTP 插件后端已按此实现（`x/rewriter/plugin/{grpc,http}.go`）。为头复用该接口，采用**头块序列化**：

- **序列化**：`http.Header.Write(buf)` → MIME 字节（`Key: value\r\n`，多值 `Set-Cookie` 一值一行）
- **插件调用**：`rw.Rewriter.Rewrite(ctx, buf.Bytes(), MetadataRewriteOption(rewriteMeta(...)))`
- **解析回**：`textproto.ReadMIMEHeader` → `http.Header`

插件可增删改任意头；`Name` 正则作为"是否调用插件"的门控（与 body 的 `shouldApply`/`Pattern` 门控同构，`sniffer_sse.go:491-493`）。零改动 `core/`、`plugin/`、`gost-plugins/`。

⚠️ **序列化/解析回的两个保真度细节（落地时已踩坑并修复）**：

- `http.Header.Write` 只输出 `Key: value\r\n` 行、**不带结尾空行**，而 `textproto.ReadMIMEHeader` 需要空行才能判定结束 → 序列化后必须补 `\r\n`；插件输出缺结尾空行时解析前补 `\r\n`。
- `http.Header.Write` 会**排序** key、`ReadMIMEHeader` 会**规范化**名字——插件拿到的头块不是线序/原始字节。正则场景无影响，但需在 `HTTPHeaderRewriteSettings.Rewriter` 注释里点明该保真度上限。

## 核心设计 C：元数据标准化（`kind` + 收敛公共字段）

现状：插件元数据是**四处手搓 map**，公共字段 `sid/direction/uri` 反复复制，且全部缺 `kind`：

- `baseMetadata()`（`sniffer_sse.go:380-396`）——非 SSE body 路径
- SSE 三个内联 map（`sniffer_sse.go:299`、`:323`、`:353`）——各自再拼 `sse_phase`/`event_index`/`stream_error`

本次加头重写是**第六个使用点**。收敛到一个共享 helper，公共字段统一为 `sid / direction / uri / kind`：

新增 `x/internal/util/forwarder/rewrite_metadata.go`：

```go
// Rewriter-plugin metadata common fields (JSON convention, opaque to
// core/plugin — carried in RewriteRequest.Metadata).
const (
	MetaKeySid       = "sid"
	MetaKeyDirection = "direction"
	MetaKeyURI       = "uri"
	MetaKeyKind      = "kind"
)

// kind values: what the plugin is receiving (byte payload vs header block).
const (
	KindBody   = "body"
	KindHeader = "header"
)

// rewriteMeta builds the standard plugin metadata: sid/direction/uri/kind
// plus dimension-specific extras. Empty common fields are omitted so plugins
// can rely on presence rather than empty strings.
func rewriteMeta(sid, direction, uri, kind string, extras map[string]any) map[string]any {
	md := map[string]any{}
	if sid != "" { md[MetaKeySid] = sid }
	if direction != "" { md[MetaKeyDirection] = direction }
	if uri != "" { md[MetaKeyURI] = uri }
	if kind != "" { md[MetaKeyKind] = kind }
	maps.Copy(md, extras)
	return md
}
```

改造：

- `baseMetadata()` → `return rewriteMeta(b.sid, b.direction, b.uri, KindBody, nil)`
- 三个 SSE 内联 map → `rewriteMeta(..., KindBody, map[string]any{"sse_phase": ..., "event_index": ...})`（`stream_error` 同理）
- 头重写 → `rewriteMeta(sid, direction, uri, KindHeader, nil)`

`kind` 为**新增字段**，对现有插件（llm-api-converter 等）是加法式向后兼容——未知字段忽略。`direction` 沿用既有取值 `"request"/"response"`。

## 代码改动（5 处，全部镜像现有 body-rewrite 模式）

### 1. `core/chain/node.go` — 纯数据结构体

> ✅ **已获批**：用户确认 core/ 可修改（2026-08-28）。本改动是既有 body-rewrite 模式的延续（`HTTPBodyRewriteSettings` :55、`RewriteRequestBody`/`RewriteResponseBody` :84-86 已同构引入），非新创接口。

`HTTPNodeSettings`（:71-89）加两个字段：

```go
// RewriteRequestHeader holds the request-header rewrite rules.
RewriteRequestHeader  []HTTPHeaderRewriteSettings
// RewriteResponseHeader holds the response-header rewrite rules.
RewriteResponseHeader []HTTPHeaderRewriteSettings
```

新增结构体（对齐 `HTTPBodyRewriteSettings` :54-69，MIME Type→Name、去 MaxChunkSize）：

```go
// HTTPHeaderRewriteSettings defines an HTTP header rewrite rule.
type HTTPHeaderRewriteSettings struct {
	// Name is the regex matched against header names (case-insensitive).
	// In plugin mode it gates whether the plugin is invoked.
	// Note: *regexp.Regexp (not string like HTTPBodyRewriteSettings.Type)
	// is intentional — header *names* need regex matching, while body rules
	// match a MIME prefix. Do not "align" this back to string.
	Name *regexp.Regexp
	// Pattern is the regex matched against each header value (regex mode);
	// in plugin mode it is unused.
	Pattern *regexp.Regexp
	// Replacement is the replacement bytes (regex mode).
	Replacement []byte
	// Rewriter is an optional plugin-based rewriter. When set, Rewrite
	// delegates to the plugin over the serialized header block. The plugin
	// receives a sorted, canonicalized header block (http.Header.Write
	// normalizes names and sorts keys), not the original wire bytes.
	Rewriter rewriter.Rewriter
}
```

### 2. `x/config/config.go` — 配置结构

`HTTPNodeConfig`（:505-530）加两个字段（与 `RewriteRequestBody`/`RewriteResponseBody` 对称）：

```go
// rewrite request header values
RewriteRequestHeader  []HTTPHeaderRewriteConfig `yaml:"rewriteRequestHeader,omitempty" json:"rewriteRequestHeader,omitempty"`
// rewrite response header values
RewriteResponseHeader []HTTPHeaderRewriteConfig `yaml:"rewriteResponseHeader,omitempty" json:"rewriteResponseHeader,omitempty"`
```

新增（对齐 `HTTPBodyRewriteConfig` :457-465）：

```go
type HTTPHeaderRewriteConfig struct {
	// Name is the header name regex, e.g. "(?i)^(location|set-cookie)$".
	Name string
	// Match is the header value regex.
	Match string
	// Replacement is the replacement string.
	Replacement string
	// Rewriter is the name of the rewriter plugin (via registry).
	Rewriter string `yaml:",omitempty" json:"rewriter,omitempty"`
}
```

### 3. `x/config/parsing/node/parse.go` — 解析

新增 `parseHeaderRewrites(vs []config.HTTPHeaderRewriteConfig, log logger.Logger) []chain.HTTPHeaderRewriteSettings`，镜像 `parseBodyRewrites`（:89-144）：

- `Name` 与 `Match` 各自 `regexp.Compile`（`Match` 为空 → Pattern nil；`Name` 为空但 `Rewriter` 非空 → 插件门控"始终调用"）
- `v.Rewriter != ""` → `registry.RewriterRegistry().Get()`（未注册 `log.Warnf`，同 :133-138）
- ⚠️ **空 Name 门控必须用配置字符串判空**：`regexp.Compile("")` 返回**非 nil** 的 match-all 正则。若拿编译结果 `name != nil` 判空，`name: ""` + 无 rewriter 的规则会通过门控、对每个头名匹配但 `Pattern==nil` 跳过值 → **静默 no-op**。正确做法：append 门控判 `v.Name != "" || rw.Rewriter != nil`（编译前，用 `v.Name` 字符串）；插件"始终调用"门控在 `v.Name == ""` 且 `v.Rewriter != ""` 时把 `Name` 字段留 nil。

组装块（:315-357）追加：

```go
settings.RewriteRequestHeader = parseHeaderRewrites(cfg.HTTP.RewriteRequestHeader, log)
settings.RewriteResponseHeader = parseHeaderRewrites(cfg.HTTP.RewriteResponseHeader, log)
```

### 4. `x/internal/util/forwarder/rewrite_metadata.go` — 新增

`rewriteMeta()` helper + `MetaKey*`/`Kind*` 常量（见核心设计 C）。

### 5. `x/internal/util/forwarder/sniffer_rewrite.go` + `sniffer_http.go` — 头重写实现 + 接线

`rewriteRespBody`（:44）的兄弟；新增一个共享实现 + 两个薄封装：

```go
// rewriteHeaderBlock applies the rewrite chain to h in place.
func rewriteHeaderBlock(ctx context.Context, h http.Header, rewrites []chain.HTTPHeaderRewriteSettings, direction, uri string) error
```

语义（逐规则）：

- **插件模式**（`rw.Rewriter != nil`）：
  - 门控：`rw.Name == nil` 或存在任一头名匹配 `rw.Name`（大小写不敏感）→ 否则跳过
  - 序列化整个 `h`（补结尾空行）→ 插件（元数据 `rewriteMeta(sid, direction, uri, KindHeader, nil)`）→ `textproto.ReadMIMEHeader` 解析回 → 替换 `h`
  - ⚠️ **`h` 是 map，不可靠函数内重赋值**：`h = newHeader` 只改形参引用、调用方无感。必须 `clear(h)` 后从解析结果逐 key 拷贝回（或 `maps.Copy`）。
- **正则模式**（`rw.Rewriter == nil && rw.Name != nil`）：
  - 遍历头名匹配 `rw.Name` 的头（`strings.ToLower` 双方归一）
  - 每个值独立 `rw.Pattern.ReplaceAll`（`Pattern == nil` 跳过该值）
  - 替换结果为空 → 丢弃该值；该头值全空 → `h.Del(name)`（**删除语义**，沿用 `RequestHeader` `v=="" → Del` 的既有约定，`sniffer_http.go:467-474`）

薄封装：

```go
func rewriteReqHeader(ctx context.Context, req *http.Request, rewrites ...) error
func rewriteRespHeader(ctx context.Context, resp *http.Response, rewrites ...) error
```

（`req.Header`/`resp.Header` nil 守卫；`direction`="request"/"response"，`uri`=`req.RequestURI`。）

**`httpRoundTrip`** 接线（行号已核对）：

- 请求侧：`hasReqRewrite`（:413-415）追加 `|| len(httpSettings.RewriteRequestHeader) > 0`；捕获 `reqHeaderRewrites`；在 RequestHeader 注入（:467-474）与 RewriteURL（:476-492）**之后**、body 快照（:502）之前调用 `rewriteReqHeader`（先于 :518/522 的 `req.Write(cc)` 上游写出）
  - ⚠️ **recorder 请求侧保真度**：`ro.HTTP.Request.Header` 最后一次赋值在 `:473`（静态注入循环内），`rewriteReqHeader` 插在它之后 → recorder 仍显示删除前的 `Referer`/`Origin`/`Cookie`。需在 `rewriteReqHeader` 后补 `ro.HTTP.Request.Header = req.Header.Clone()`。
- 响应侧：`hasRespRewrite`（:416-417）追加 `|| len(httpSettings.RewriteResponseHeader) > 0`；捕获 `respHeaderRewrites`；在静态 `responseHeader` 覆盖块（:622-629）**之后**、:630 `ro.HTTP.Response.Header.Clone()` 之前调用 `rewriteRespHeader`（recorder 记录改写后结果；满足 :620-621 的 Content-Type 顺序约束）

## 配置：完整 GitHub 镜像参考（`play/github-mirror.yaml`）

```yaml
services:
- name: github-mirror
  addr: :8080
  handler:
    type: tcp
    metadata:
      sniffing: true
  listener:
    type: tcp
  forwarder:
    nodes:
    - name: github
      matcher:
        rule: PathPrefix(`/github.com/`) || PathPrefix(`/www.github.com/`)
      addr: github.com:443
      tls: { secure: true }
      http:
        host: github.com                    # 静态 Host（回程还原，替代 hostFromPathPrefix）
        rewriteURL:
        - match: '^/github\.com/'
          replacement: '/'                  # 剥 path 首段
        rewriteResponseBody:
        - type: text/html
          match: 'https://(github\.com|www\.github\.com|gist\.github\.com)'
          replacement: 'https://127.0.0.1:8080/$1'
          maxChunkSize: 8388608
        rewriteRequestHeader:
        - name: '(?i)^(referer|origin|x-forwarded-host)$'
          match: '.*'
          replacement: ''                  # 删除：客户端 Referer 已是 mirror URL，回传上游会泄漏 mirror host
        rewriteResponseHeader:
        - name: '(?i)^location$'
          match: 'https://(github\.com|www\.github\.com|gist\.github\.com)'
          replacement: 'https://127.0.0.1:8080/$1'
        - name: '(?i)^set-cookie$'
          match: 'Domain=\.?github\.com;?\s*'
          replacement: ''
        - name: '(?i)^content-security-policy(-report-only)?$'
          match: '.*'
          replacement: ''                  # 值空 → 删头
        - name: '(?i)^strict-transport-security$'
          match: '.*'
          replacement: ''
    - name: ghusercontent
      matcher:
        rule: PathPrefix(`/raw.githubusercontent.com/`) || PathPrefix(`/avatars.githubusercontent.com/`) || PathPrefix(`/objects.githubusercontent.com/`)
      addr: raw.githubusercontent.com:443
      tls: { secure: true }
      http:
        host: raw.githubusercontent.com
        rewriteURL:
        - match: '^/raw\.githubusercontent\.com/'
          replacement: '/'
        # 匿名场景：剥 Domain 后 session cookie 会随 /raw.../ 路径跨 origin 泄漏，必须删
        rewriteRequestHeader:
        - name: '(?i)^cookie$'
          match: '.*'
          replacement: ''
        # body/header 同 github 节点，match 换成 githubusercontent 域名
```

> ⚠️ **单 origin 约束**：SNI/拨号目标钉死在 `node.Addr`（`github.com:443`），故一个 node 只能正确服务一个 origin。`www.github.com` 复用 github node 可行（github 证书含 `*.github.com`）；`gist.github.com` 须**单独 node**（`addr: gist.github.com:443` + 自己的 `host`/`rewriteURL`），不可塞进 github node 的 matcher。e2e 须单独验证 gist 回程。

说明：

- **出程编码**：body/header 正则把 `https://<origin-host>/...` 换成 `https://MIRROR_HOST/<origin-host>/...`，`$1` 捕获 host 整段，明文前缀直接可读。
- **回程解码**：客户端请求 `GET /github.com/ginuerzh/gost`（Host=`MIRROR_HOST`），node 按 `PathPrefix('/github.com/')` 选中，`rewriteURL` 剥前缀 → `/ginuerzh/gost`，`http.host` 还原 `req.Host=github.com`。
- **正则捕获组**：Go RE2 不支持 `(?:)` 非捕获组，`(a|b)` 交替按需编号 `$1`。`githubusercontent` 子域清单（raw/avatars/objects/camo/media/cloud/codeload）实现时按真实资源需求枚举 node + PathPrefix，可合并到一个 node 用 `PathRegexp`。

## 验证

1. `cd x && go build ./... && go vet ./...`；`cd ../core && go build ./... && go vet ./...`
2. 单测（`x/internal/util/forwarder/`，参考现有 rewrite 测试风格）：
   - `rewriteHeaderBlock` 正则模式：Location 改写、多值 Set-Cookie 逐值改写、`.*`→`` 删头、头名大小写混排、`Name` 不匹配时不动
   - 插件模式：fake `Rewriter`（`type fakeRewriter func(...)`）验证门控 + 序列化/解析回 round-trip + 元数据含 `kind:"header"`
   - 插件模式 `clear`+拷贝语义：fake `Rewriter` 返回增/删/改头块后，验证调用方 `http.Header` 被原地更新（`h = newHeader` 重赋值不生效的坑）
   - 插件 round-trip 补结尾空行：验证 `http.Header.Write` 无空行、插件输出无空行两种情况下解析都不报 EOF
   - `rewriteMeta`：非空字段保留、空字段省略；`KindBody`/`KindHeader` 正确落位；SSE 三处 map 改造后 `sse_phase`/`event_index` extra 与公共字段并存
   - 空 `Name` 门控：`name: ""` + 无 rewriter → **不 append**（防静默 no-op，见 parse 警告）
3. e2e（真实 github.com + curl，沿用上轮已跑通的镜像 config）：
   - `curl -si http://127.0.0.1:8080/github.com/...` 验证：302 `Location` 指向 `127.0.0.1:8080/<host>/...`、`Set-Cookie` 无 `Domain=github.com`、`content-security-policy` 头消失
   - 验证请求 `Referer`/`Origin`/`X-Forwarded-Host` 已删除（上游收不到 mirror host）；body 里 `https://github.com/...` 全换成 `https://127.0.0.1:8080/github.com/...`（复跑 `/explore` 回归，替换不残留）
   - **闭环回归**：`curl` 跟着 body 里改写后的 URL 二次请求，确认路由回正确 origin 且内容可加载
   - **剥前缀边界**：`rewriteURL` 的 `match` 作用于 `req.URL.Path`，`PathPrefix('/github.com/')` 已含尾斜杠，剥完是 `/...`，行为正确——单独验证一次
4. `CGO_ENABLED=1 go test -race ./internal/util/forwarder/...`

## 不做（明确留白）

- JS 运行时注入的 URL（用户明确排除）
- **登录态**：v1 边界 = 匿名只读浏览 + 公开仓库/raw/avatars 资源浏览下载。登录链路有硬断点（CAPTCHA 第三方 iframe 未镜像、WebAuthn `rpId` 绑 github.com、SAML/SSO 回调 RelayState 绑 origin、Secure cookie 要求 HTTPS），不保证、不投精力。v1 匿名场景下仍需处理**跨 origin Cookie 泄漏**：ghusercontent 节点加 `rewriteRequestHeader` 删除 `Cookie`，防止剥 Domain 后 session cookie 随 `/raw.../` 路径泄漏到 githubusercontent 上游
- base64url host 前缀——明文前缀 github 场景够用；需要支持任意 host（含 `:` `/` 特殊字符）时再加：编码走插件
- 头重写的 `delete bool` 显式字段——用 `match: '.*'` + `replacement: ''` 表达删除
- 扩展 `core/rewriter.Rewriter` 接口为结构化头接口——字节式序列化已复用现有插件链路，零改动
- githubusercontent 各子域 SNI 动态化（node addr 固定、tls.serverName 静态）——多子域真实 SNI 需按回程 host 联动 `tlsWrapConn`，属部署细节，e2e 遇到再补
- gist 单独 node（`addr: gist.github.com:443`）的 SNI/证书验证——单 origin 约束见 config 内警告，e2e 单独跑 gist 回程
- 修正 `x/CLAUDE.md` 过时描述（"There are no tests in this module"）——`x/` 下现有 182 个 `_test.go`，本次在 `x/internal/util/forwarder/` 加单测符合现状，无需为加测改文档
