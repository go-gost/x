# 多 IP 候选拨号失败转移 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 chain 节点地址在 hosts/resolver 返回的多个 IP 之间分散流量并失败转移，坏候选短期降权。

**Architecture:** `xnet.Resolve` 目前把候选塌缩成 `ips[0]`；新增 `xnet.ResolveAll` 保留全量候选，`Resolve` 改为取第一个（所有既有调用点行为不变）。`chainRoute.connect` 的首跳把候选分成「健康」和「TTL 内失败」两组，健康组洗牌在前、失败组在后，逐个 `Dial`+`Handshake`，成功即用，全失败才标记节点故障。

**Tech Stack:** Go（`x/` 模块，`github.com/go-gost/x`）、`math/rand/v2`、testify。

**Spec:** `x/docs/superpowers/specs/2026-10-25-resolve-multi-ip-failover-design.md`

## Global Constraints

- 只改 `x/`，**不动 `core/`**：不往 `NodeOptions` 加字段。
- 不引入新的第三方依赖；`x/go.mod` 不变。
- 代码注释与日志一律英文。
- **随机只发生在 `connect()` 内部的候选顺序**；`Resolve` 的返回值仍必须确定（它参与 `Chain.Route()` 分流判定）。
- 健康候选之间必须均匀随机（多 IP 的负载均衡不能被退化成主备）。
- 后续跳（hop ≥ 1）的 `Connect` 不做失败转移。
- 测试按包跑（通配符 `go test ./...` 在本机会挂）：`go test ./chain/ -count=1`、`go test ./internal/net/ -count=1`。

## Review Focus

- **resolver 返回 `resolver.ErrInvalid`**（如 unix 网络）：必须原样返回 addr，不能被当成"域名不存在"报错 → Task 1 `TestResolveAll_ResolverErrInvalid`。
- **resolver 返回 0 个 IP 且无错误**：必须报 `resolver: domain <host> does not exist`，否则 `connect` 会拿空候选去 Dial → Task 1 `TestResolveAll_ResolverEmpty`。
- **空地址 / 无端口的地址**（`""`、`:8080`）：保持原样返回单元素，connect 行为不变 → Task 1 `TestResolveAll_EmptyAddr`、`TestResolveAll_NoHost`。
- **候选全部失败**：必须 `Marker().Mark()` 且只 Mark 一次，不能提前 Mark 使节点在还有可用 IP 时被跳过 → Task 2 `TestChainRoute_Connect_AllCandidatesFail`（断言 `Marker().Count() == 1`）。
- **健康时不能退化成主备**：所有候选都健康时，首个被拨的地址必须随连接变化（负载均衡），而不是固定第一个 → Task 2 `TestChainRoute_Connect_SpreadAcrossHealthyCandidates`。
- **坏候选的降权必须会过期**：否则一个临时抖动的 IP 会被永久排到最后，直到进程重启 → Task 2 `TestOrderCandidates_ExpiresAfterTTL`。

---

### Task 1: `xnet.ResolveAll` 返回全部候选

**Files:**
- Modify: `x/internal/net/resolve.go:20-75`
- Test: `x/internal/net/resolve_test.go`

**Interfaces:**
- Consumes: 既有的 `resolver.Resolver`、`hosts.HostMapper`、`logger.Logger`。
- Produces: `ResolveAll(ctx context.Context, network, addr string, r resolver.Resolver, hosts hosts.HostMapper, log logger.Logger) ([]string, error)`；`Resolve` 签名不变（`(string, error)`）。

- [ ] **Step 1: 写失败测试**

在 `x/internal/net/resolve_test.go` 末尾追加（文件头需补 `"errors"`、`"github.com/stretchr/testify/require"`）：

```go
func TestResolveAll_HostMapperMultipleIPs(t *testing.T) {
	mapper := &mockHostMapper{ips: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}}
	addrs, err := ResolveAll(context.Background(), "tcp", "example.com:8080", nil, mapper, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.1:8080", "10.0.0.2:8080"}, addrs)
}

func TestResolveAll_HostMapperDedup(t *testing.T) {
	mapper := &mockHostMapper{ips: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.1")}}
	addrs, err := ResolveAll(context.Background(), "tcp", "example.com:8080", nil, mapper, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.1:8080"}, addrs)
}

func TestResolveAll_ResolverMultipleIPs(t *testing.T) {
	r := &mockResolver{ips: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")}}
	addrs, err := ResolveAll(context.Background(), "tcp", "example.com:8080", r, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"192.168.1.1:8080", "192.168.1.2:8080"}, addrs)
}

func TestResolveAll_NoResolverNoHosts(t *testing.T) {
	addrs, err := ResolveAll(context.Background(), "tcp", "example.com:8080", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"example.com:8080"}, addrs)
}

func TestResolveAll_EmptyAddr(t *testing.T) {
	addrs, err := ResolveAll(context.Background(), "tcp", "", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{""}, addrs)
}

func TestResolveAll_NoHost(t *testing.T) {
	addrs, err := ResolveAll(context.Background(), "tcp", ":8080", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{":8080"}, addrs)
}

func TestResolveAll_ResolverErrInvalid(t *testing.T) {
	r := &mockResolver{err: resolver.ErrInvalid}
	addrs, err := ResolveAll(context.Background(), "unix", "/tmp/x.sock", r, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"/tmp/x.sock"}, addrs)
}

func TestResolveAll_ResolverEmpty(t *testing.T) {
	r := &mockResolver{}
	_, err := ResolveAll(context.Background(), "tcp", "gone.example:80", r, nil, nil)
	require.ErrorContains(t, err, "does not exist")
}

func TestResolve_ReturnsFirstCandidate(t *testing.T) {
	mapper := &mockHostMapper{ips: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}}
	addr, err := Resolve(context.Background(), "tcp", "example.com:8080", nil, mapper, nil)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1:8080", addr)
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd x && go test ./internal/net/ -run 'TestResolveAll|TestResolve_ReturnsFirstCandidate' -count=1`
Expected: FAIL — `undefined: ResolveAll`（编译失败）。

- [ ] **Step 3: 实现**

在 `x/internal/net/resolve.go` 中新增 `ResolveAll`，并把现有 `Resolve` 改成薄封装：

- `hosts != nil` 且 `Lookup` 返回非空：把每个 IP 用 `net.JoinHostPort(ip.String(), port)` 拼成候选，**跳过重复项**（同一 IP 只保留一次），按原顺序返回全部；同时保留原有的 `log.Debugf("hit host mapper: %s -> %s", host, ips)`。
- `r != nil`：`r.Resolve` 返回 `resolver.ErrInvalid` 时返回 `[]string{addr}, nil`；返回其它错误时 `log.Error(err)` 后继续判断；`len(ips) == 0` 时返回 `nil, fmt.Errorf("resolver: domain %s does not exist", host)`；否则按原顺序返回全部候选。
- 两者都没有：返回 `[]string{addr}, nil`。
- `addr == ""` 或 `net.SplitHostPort` 解析出空 host：返回 `[]string{addr}, nil`。
- `Resolve` 调用 `ResolveAll`：`err != nil` 返回 `("", err)`；`len(addrs) == 0` 返回 `("", nil)`；否则返回 `addrs[0]`。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd x && go test ./internal/net/ -count=1`
Expected: PASS（含既有用例）。

- [ ] **Step 5: Commit**

```bash
cd /root/code/go-gost/x
git add internal/net/resolve.go internal/net/resolve_test.go
git commit -m "feat(net): add ResolveAll returning all resolved candidates"
```

---

### Task 2: 首跳候选随机分散 + 失败降权 + 失败转移

**Files:**
- Create: `x/chain/addr.go`
- Modify: `x/chain/route.go`（`connect()` 的首跳段，约 231-270 行）
- Test: `x/chain/route_test.go`

**Interfaces:**
- Consumes: `xnet.ResolveAll(ctx, network, addr, r, hosts, log) ([]string, error)`（Task 1）。
- Produces（均在 `x/chain` 包内，unexported）：
  - `func orderCandidates(nodeAddr string, addrs []string) []string`
  - `func markAddrFailed(nodeAddr, addr string)`
  - `func markAddrOK(nodeAddr, addr string)`
  - `var addrFailTTL time.Duration`（默认 `30 * time.Second`）
  - `var timeNow func() time.Time`（默认 `time.Now`，测试可替换）

- [ ] **Step 1: 写失败测试**

新建 `x/chain/route_test.go`：

```go
package chain

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/hosts"
	xlogger "github.com/go-gost/x/logger"
	"github.com/stretchr/testify/require"
)

type routeHostMapper struct {
	m map[string][]net.IP
}

func (h *routeHostMapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	ips, ok := h.m[host]
	return ips, ok
}

// newFailoverNode builds a single node whose host resolves to two IPs
// (10.0.0.1, 10.0.0.2) and records every dialed address in dialed.
func newFailoverNode(t *testing.T, nodeAddr, host string, shouldFail func(addr string) bool, dialed *[]string, mu *sync.Mutex) (*chain.Node, *chainRoute) {
	t.Helper()
	d := &testDialer{dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
		mu.Lock()
		*dialed = append(*dialed, addr)
		mu.Unlock()
		if shouldFail(addr) {
			return nil, errors.New("dial failed")
		}
		return &testConn{}, nil
	}}
	node := chain.NewNode("n1", nodeAddr,
		chain.TransportNodeOption(NewTransport(d, &plainConnector{})),
		chain.HostMapperNodeOption(&routeHostMapper{m: map[string][]net.IP{
			host: {net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
		}}),
	)
	rt := NewRoute()
	rt.addNode(node)
	return node, rt
}

func TestChainRoute_Connect_FailoverToSecondCandidate(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	_, rt := newFailoverNode(t, "failover-1.test:443", "failover-1.test",
		func(addr string) bool { return addr == "10.0.0.1:443" }, &dialed, &mu)

	conn, err := rt.connect(context.Background(), xlogger.Nop())
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.ElementsMatch(t, []string{"10.0.0.1:443", "10.0.0.2:443"}, dialed)
}

func TestChainRoute_Connect_SpreadAcrossHealthyCandidates(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	_, rt := newFailoverNode(t, "failover-spread.test:443", "failover-spread.test",
		func(string) bool { return false }, &dialed, &mu)

	first := map[string]int{}
	for i := 0; i < 50; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		first[dialed[0]]++
	}
	require.Contains(t, first, "10.0.0.1:443")
	require.Contains(t, first, "10.0.0.2:443")
}

func TestChainRoute_Connect_DeprioritizesFailedCandidate(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	_, rt := newFailoverNode(t, "failover-deprio.test:443", "failover-deprio.test",
		func(addr string) bool { return addr == "10.0.0.1:443" }, &dialed, &mu)

	_, err := rt.connect(context.Background(), xlogger.Nop())
	require.NoError(t, err)

	for i := 0; i < 20; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		require.Equal(t, "10.0.0.2:443", dialed[0])
	}
}

func TestChainRoute_Connect_AllCandidatesFail(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	node, rt := newFailoverNode(t, "failover-allfail.test:443", "failover-allfail.test",
		func(string) bool { return true }, &dialed, &mu)

	conn, err := rt.connect(context.Background(), xlogger.Nop())
	require.Error(t, err)
	require.Nil(t, conn)
	require.Len(t, dialed, 2)
	require.EqualValues(t, 1, node.Marker().Count())
}

func TestOrderCandidates_ExpiresAfterTTL(t *testing.T) {
	oldNow, oldTTL := timeNow, addrFailTTL
	t.Cleanup(func() { timeNow, addrFailTTL = oldNow, oldTTL })

	failedAt := time.Now()
	timeNow = func() time.Time { return failedAt }
	addrFailTTL = 30 * time.Second

	nodeAddr := "failover-ttl.test:443"
	markAddrFailed(nodeAddr, "10.0.0.1:443")
	require.Equal(t, "10.0.0.2:443", orderCandidates(nodeAddr, []string{"10.0.0.1:443", "10.0.0.2:443"})[0])

	timeNow = func() time.Time { return failedAt.Add(31 * time.Second) }
	_, ok := failedAddrs.Load(addrKey(nodeAddr, "10.0.0.1:443"))
	require.False(t, ok, "expired failure record must be dropped")
}

func TestMarkAddrOK_ClearsFailure(t *testing.T) {
	nodeAddr := "failover-ok.test:443"
	markAddrFailed(nodeAddr, "10.0.0.1:443")
	markAddrOK(nodeAddr, "10.0.0.1:443")
	_, ok := failedAddrs.Load(addrKey(nodeAddr, "10.0.0.1:443"))
	require.False(t, ok)
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd x && go test ./chain/ -run 'TestChainRoute_Connect_|TestOrderCandidates_|TestMarkAddrOK_' -count=1`
Expected: FAIL — `undefined: orderCandidates` 等（编译失败）；实现后 `FailoverToSecondCandidate` 在修复前只会拨第一个候选。

- [ ] **Step 3: 实现 `x/chain/addr.go`**

```go
package chain

import (
	"math/rand/v2"
	"sync"
	"time"
)

// addrFailTTL is how long a candidate that failed to dial stays deprioritized.
// A var (not a const) so tests can shorten it.
var addrFailTTL = 30 * time.Second

// timeNow is replaceable in tests.
var timeNow = time.Now

// failedAddrs maps a "nodeAddr|candidate" key to the time of the last failure.
var failedAddrs sync.Map

func addrKey(nodeAddr, addr string) string {
	return nodeAddr + "|" + addr
}

// orderCandidates shuffles healthy candidates to the front and recently
// failed ones to the back, so a broken address does not get dialed first
// while the remaining ones keep sharing the load evenly.
func orderCandidates(nodeAddr string, addrs []string) []string {
	healthy := make([]string, 0, len(addrs))
	failed := make([]string, 0, len(addrs))

	now := timeNow()
	for _, addr := range addrs {
		key := addrKey(nodeAddr, addr)
		if v, ok := failedAddrs.Load(key); ok {
			if t, ok := v.(time.Time); ok && now.Sub(t) < addrFailTTL {
				failed = append(failed, addr)
				continue
			}
			failedAddrs.Delete(key)
		}
		healthy = append(healthy, addr)
	}

	rand.Shuffle(len(healthy), func(i, j int) { healthy[i], healthy[j] = healthy[j], healthy[i] })
	rand.Shuffle(len(failed), func(i, j int) { failed[i], failed[j] = failed[j], failed[i] })

	return append(healthy, failed...)
}

// markAddrFailed records that dialing addr failed for the given node.
func markAddrFailed(nodeAddr, addr string) {
	failedAddrs.Store(addrKey(nodeAddr, addr), timeNow())
}

// markAddrOK clears the failure record so the candidate rejoins the rotation.
func markAddrOK(nodeAddr, addr string) {
	failedAddrs.Delete(addrKey(nodeAddr, addr))
}
```

- [ ] **Step 4: 改写 `connect()` 首跳**

`x/chain/route.go` 中从 `addr, err := xnet.Resolve(ctx, network, node.Addr, ...)` 到 `cn, err := node.Options().Transport.Handshake(ctx, cc)` 这一段替换为：

```go
addrs, err := xnet.ResolveAll(ctx, network, node.Addr, node.Options().Resolver, node.Options().HostMapper, logger)
marker := node.Marker()
if err != nil {
	if marker != nil {
		marker.Mark()
	}
	return
}

start := time.Now()
var cn net.Conn
for _, addr := range orderCandidates(node.Addr, addrs) {
	cc, derr := node.Options().Transport.Dial(ctx, addr)
	if derr != nil {
		err = derr
		markAddrFailed(node.Addr, addr)
		continue
	}
	hn, herr := node.Options().Transport.Handshake(ctx, cc)
	if herr != nil {
		cc.Close()
		err = herr
		markAddrFailed(node.Addr, addr)
		continue
	}
	markAddrOK(node.Addr, addr)
	cn, err = hn, nil
	break
}
if err != nil {
	if marker != nil {
		marker.Mark()
	}
	return
}
if marker != nil {
	marker.Reset()
}
```

其余部分（`MetricNodeConnectDurationObserver`、`preNode` 循环、末尾 `conn = cn`）不变；`defer` 里按 `err` 标记链错误的逻辑也不变。

- [ ] **Step 5: 运行测试确认通过**

Run: `cd x && go test ./chain/ -run 'TestChainRoute_Connect_|TestOrderCandidates_|TestMarkAddrOK_' -count=1`
Expected: PASS（六个用例）。

- [ ] **Step 6: 跑整包回归**

Run: `cd x && go test ./chain/ ./internal/net/ -count=1`
Expected: PASS。

- [ ] **Step 7: Commit**

```bash
cd /root/code/go-gost/x
git add chain/addr.go chain/route.go chain/route_test.go
git commit -m "feat(chain): spread and fail over across resolved node addresses"
```

---

### Task 3: 静态检查与整体回归

**Files:** 无新增。

- [ ] **Step 1: vet**

Run: `cd x && go vet ./chain/ ./internal/net/`
Expected: 无输出。

- [ ] **Step 2: 受影响包的完整测试**

Run: `cd x && go test ./chain/ ./internal/net/ ./config/parsing/node/ -count=1`
Expected: PASS。

- [ ] **Step 3: 编译 gost 主程序**

Run: `cd /root/code/go-gost/gost && go build ./cmd/gost`
Expected: 成功（工作区开着，用的是本地 `x/`）。

- [ ] **Step 4: 真机回归（pi）**

把 `gost:hosts` 里 `relay.gost.run` 的其中一条记录换成不可达地址，验证两件事：新建连接在一次失败后仍能落到可用 IP；把两条都恢复后，日志里两条 IP 都重新出现（负载均衡未退化）。验证完恢复 hosts 记录。

---

## Self-Review

- 规格覆盖：`ResolveAll`（Task 1）、随机分散 + TTL 降权 + 失败转移（Task 2）、后续跳不做（约束）、不改 core（约束）、随机不进入 `Resolve`（约束）✔
- 类型一致：`ResolveAll` 签名在 Task 1/2 一致；`orderCandidates`/`markAddrFailed`/`markAddrOK`/`addrKey`/`failedAddrs`/`addrFailTTL`/`timeNow` 在 Task 2 定义并使用 ✔
- Review Focus 六条均有对应测试 ✔
