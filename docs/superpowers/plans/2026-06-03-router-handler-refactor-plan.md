# Router Handler Refactor + Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `x/handler/router/` — extract `conn.go` and `observe.go`, fix the `DelConnector` missing-break bug, and write ~120-150 unit tests across 8 test files.

**Architecture:** Keep all code in `package router` (no sub-packages). Extract two new source files via pure move operations. Add comprehensive test coverage for all exported and internal functions using standard Go test patterns (fake connections, pipe-based integration, mock interfaces).

**Tech Stack:** Go, relay protocol library, standard library `testing` package

---

## File Structure

### Source files (before → after)

| File | Status | Lines | Content |
|------|--------|-------|---------|
| `handler/router/associate.go` | Unchanged | 358→~245 | `handleAssociate` + `handlePacket` + `getRoute` + `getAddrforRoute` + `sdRenew` |
| `handler/router/entrypoint.go` | Unchanged | 64 | `handleEntrypoint` |
| `handler/router/handler.go` | Trimmed | 297→~235 | `routerHandler`, `NewHandler`, `Init`, `Handle`, `Close` (moved observeStats/checkRateLimit out) |
| `handler/router/metadata.go` | Unchanged | 86 | `metadata` struct, `parseMetadata`, constants |
| `handler/router/router.go` | Fix one bug | 251 | `Router`, `Connector`, `ConnectorPool`, `parseRouterID` |
| `handler/router/conn.go` | **New (extract)** | ~60 | `packetConn`, `lockWriter`, `LockWriter` (from associate.go) |
| `handler/router/observe.go` | **New (extract)** | ~40 | `observeStats`, `checkRateLimit` (from handler.go) |

### Test files (all new)

| File | Tests | Focus |
|------|-------|-------|
| `handler/router/helpers_test.go` | — | testLogger, fakeConn, pipeConn, fakePacketConn, fakeObserver, mockAuther, mockRateLimiter, mockRouter, mockSD, mockIngress, build helpers, read helpers |
| `handler/router/metadata_test.go` | ~15 | parseMetadata: empty, full, defaults, edge cases |
| `handler/router/router_test.go` | ~25 | Connector, Router, ConnectorPool, parseRouterID |
| `handler/router/conn_test.go` | ~12 | packetConn Read/Write, lockWriter |
| `handler/router/observe_test.go` | ~10 | checkRateLimit, observeStats |
| `handler/router/handler_test.go` | ~25 | NewHandler, Init, Handle, Close |
| `handler/router/associate_test.go` | ~35 | handleAssociate, handlePacket, getRoute, getAddrforRoute, sdRenew |
| `handler/router/entrypoint_test.go` | ~8 | handleEntrypoint |

---

### Task 1: Extract conn.go from associate.go

**Files:**
- Create: `handler/router/conn.go`
- Modify: `handler/router/associate.go` — remove the extracted code

- [ ] **Step 1: Create conn.go by moving packetConn, lockWriter, and LockWriter**

Create `handler/router/conn.go` with the `packetConn` type, `lockWriter` type, and `LockWriter` function from `associate.go`. No code changes — pure move.

```go
package router

import (
    "encoding/binary"
    "errors"
    "io"
    "math"
    "net"
    "sync"

    "github.com/go-gost/core/common/bufpool"
)

type packetConn struct {
    net.Conn
}

func (c *packetConn) Read(b []byte) (n int, err error) {
    var bb [2]byte
    _, err = io.ReadFull(c.Conn, bb[:])
    if err != nil {
        return
    }
    dlen := int(binary.BigEndian.Uint16(bb[:]))
    if len(b) >= dlen {
        return io.ReadFull(c.Conn, b[:dlen])
    }
    buf := bufpool.Get(dlen)
    defer bufpool.Put(buf)
    n, err = io.ReadFull(c.Conn, buf)
    copy(b, buf[:n])
    return
}

func (c *packetConn) Write(b []byte) (n int, err error) {
    if len(b) > math.MaxUint16 {
        err = errors.New("write: data maximum exceeded")
        return
    }
    buf := bufpool.Get(len(b) + 2)
    defer bufpool.Put(buf)
    binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
    n = copy(buf[2:], b)
    return c.Conn.Write(buf)
}

type lockWriter struct {
    w  io.Writer
    mu sync.Mutex
}

func LockWriter(w io.Writer) io.Writer {
    return &lockWriter{w: w}
}

func (w *lockWriter) Write(p []byte) (int, error) {
    w.mu.Lock()
    defer w.mu.Unlock()
    return w.w.Write(p)
}

func (w *lockWriter) Close() error {
    if closer, ok := w.w.(io.Closer); ok {
        return closer.Close()
    }
    return nil
}
```

- [ ] **Step 2: Remove the extracted code from associate.go**

Delete the `packetConn`, `lockWriter`, and `LockWriter` definitions (lines 296-358) from `associate.go`. Remove unused imports (`"sync"`, `"math"`, `"errors"`, `"encoding/binary"`).

- [ ] **Step 3: Build to verify**

```bash
cd /config/workspace/go-gost/x && go build ./handler/router/ && go vet ./handler/router/
```
Expected: success, no errors.

- [ ] **Step 4: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/conn.go handler/router/associate.go
git commit -m "refactor(handler/router): extract conn.go (packetConn, lockWriter) from associate.go"
```

---

### Task 2: Extract observe.go from handler.go

**Files:**
- Create: `handler/router/observe.go`
- Modify: `handler/router/handler.go` — remove the extracted code

- [ ] **Step 1: Create observe.go by moving checkRateLimit and observeStats**

Create `handler/router/observe.go`:

```go
package router

import (
    "context"
    "net"
    "time"

    "github.com/go-gost/core/observer"
    "github.com/go-gost/x/internal/util/stats"
    rate_limiter "github.com/go-gost/x/limiter/rate"
)

func (h *routerHandler) checkRateLimit(addr net.Addr) bool {
    if h.options.RateLimiter == nil {
        return true
    }
    host, _, _ := net.SplitHostPort(addr.String())
    if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
        return limiter.Allow(1)
    }
    return true
}

func (h *routerHandler) observeStats(ctx context.Context) {
    if h.options.Observer == nil {
        return
    }

    var events []observer.Event

    ticker := time.NewTicker(h.md.observerPeriod)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if len(events) > 0 {
                if err := h.options.Observer.Observe(ctx, events); err != nil {
                    continue
                }
            }

            evs := h.stats.Events()
            if len(evs) > 0 {
                if err := h.options.Observer.Observe(ctx, evs); err != nil {
                    events = evs
                    continue
                }
            }
            events = nil

        case <-ctx.Done():
            return
        }
    }
}
```

- [ ] **Step 2: Remove the extracted code from handler.go**

Delete `checkRateLimit` (lines 251-261) and `observeStats` (lines 263-297) from `handler.go`. Remove unused imports: `"context"`, `"observer"` (but keep others).

- [ ] **Step 3: Build to verify**

```bash
cd /config/workspace/go-gost/x && go build ./handler/router/ && go vet ./handler/router/
```
Expected: success, no errors.

- [ ] **Step 4: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/observe.go handler/router/handler.go
git commit -m "refactor(handler/router): extract observe.go (observeStats, checkRateLimit) from handler.go"
```

---

### Task 3: Fix DelConnector bug in router.go

**Files:**
- Modify: `handler/router/router.go` — add `break` after delete

- [ ] **Step 1: Add break to prevent post-delete iteration**

In `router.go:142-146`, change:

```go
for i, c := range connectors {
    if c.id.Equal(cid) {
        r.connectors[host] = append(connectors[:i], connectors[i+1:]...)
    }
}
```

to:

```go
for i, c := range connectors {
    if c.id.Equal(cid) {
        r.connectors[host] = append(connectors[:i], connectors[i+1:]...)
        break
    }
}
```

- [ ] **Step 2: Build to verify**

```bash
cd /config/workspace/go-gost/x && go build ./handler/router/ && go vet ./handler/router/
```

- [ ] **Step 3: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/router.go
git commit -m "fix(handler/router): add break to DelConnector after successful delete"
```

---

### Task 4: Write helpers_test.go

**Files:**
- Create: `handler/router/helpers_test.go`

Contains all test infrastructure types reused across test files.

- [ ] **Step 1: Write helpers_test.go**

```go
package router

import (
    "bytes"
    "context"
    "errors"
    "io"
    "net"
    "sync"
    "time"

    "github.com/go-gost/core/auth"
    "github.com/go-gost/core/ingress"
    "github.com/go-gost/core/limiter"
    "github.com/go-gost/core/limiter/rate"
    "github.com/go-gost/core/limiter/traffic"
    "github.com/go-gost/core/logger"
    core_metadata "github.com/go-gost/core/metadata"
    "github.com/go-gost/core/observer"
    "github.com/go-gost/core/router"
    "github.com/go-gost/core/sd"
    "github.com/go-gost/relay"
    xmetadata "github.com/go-gost/x/metadata"
)

// ---------------------------------------------------------------------------
// testLogger
// ---------------------------------------------------------------------------

type testLogger struct{}

func (l *testLogger) WithFields(map[string]any) logger.Logger { return l }
func (l *testLogger) IsLevelEnabled(logger.LogLevel) bool     { return false }
func (l *testLogger) GetLevel() logger.LogLevel               { return logger.InfoLevel }
func (l *testLogger) Trace(args ...any)                       {}
func (l *testLogger) Tracef(string, ...any)                   {}
func (l *testLogger) Debug(args ...any)                       {}
func (l *testLogger) Debugf(string, ...any)                   {}
func (l *testLogger) Info(args ...any)                        {}
func (l *testLogger) Infof(string, ...any)                    {}
func (l *testLogger) Warn(args ...any)                        {}
func (l *testLogger) Warnf(string, ...any)                    {}
func (l *testLogger) Error(args ...any)                       {}
func (l *testLogger) Errorf(string, ...any)                   {}
func (l *testLogger) Fatal(args ...any)                       {}
func (l *testLogger) Fatalf(string, ...any)                   {}

// ---------------------------------------------------------------------------
// testMD
// ---------------------------------------------------------------------------

func testMD(m map[string]any) core_metadata.Metadata {
    return xmetadata.NewMetadata(m)
}

// ---------------------------------------------------------------------------
// fakeConn — bytes.Buffer-backed net.Conn
// ---------------------------------------------------------------------------

type fakeConn struct {
    net.Conn
    buf      []byte
    offset   int
    writeBuf bytes.Buffer
    closed   bool
    mu       sync.Mutex
    laddr    net.Addr
    raddr    net.Addr
}

func (c *fakeConn) Read(b []byte) (int, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.offset >= len(c.buf) {
        return 0, io.EOF
    }
    n := copy(b, c.buf[c.offset:])
    c.offset += n
    return n, nil
}

func (c *fakeConn) Write(b []byte) (int, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.writeBuf.Write(b)
}

func (c *fakeConn) Close() error {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.closed = true
    return nil
}

func (c *fakeConn) LocalAddr() net.Addr {
    if c.laddr != nil {
        return c.laddr
    }
    return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (c *fakeConn) RemoteAddr() net.Addr {
    if c.raddr != nil {
        return c.raddr
    }
    return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error   { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error  { return nil }

// ---------------------------------------------------------------------------
// pipeConn — bidirectional pipe-based net.Conn
// ---------------------------------------------------------------------------

type pipeConn struct {
    reader  *io.PipeReader
    writer  *io.PipeWriter
    laddr   net.Addr
    raddr   net.Addr
    closed  bool
    closeMu sync.Mutex
}

func newPipePair() (*pipeConn, *pipeConn) {
    pr1, pw1 := io.Pipe()
    pr2, pw2 := io.Pipe()
    a := &pipeConn{reader: pr1, writer: pw2}
    b := &pipeConn{reader: pr2, writer: pw1}
    a.laddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
    a.raddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
    b.laddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
    b.raddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
    return a, b
}

func (c *pipeConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *pipeConn) Close() error {
    c.closeMu.Lock()
    defer c.closeMu.Unlock()
    if c.closed {
        return nil
    }
    c.closed = true
    c.reader.Close()
    c.writer.Close()
    return nil
}

func (c *pipeConn) LocalAddr() net.Addr { return c.laddr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.raddr }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------------------
// fakePacketConn — channel-backed net.PacketConn
// ---------------------------------------------------------------------------

type fakePacketConn struct {
    dataCh  chan []byte
    addrCh  chan net.Addr
    closed  bool
    closeMu sync.Mutex
    laddr   net.Addr
}

func newFakePacketConn(laddr net.Addr) *fakePacketConn {
    return &fakePacketConn{
        dataCh: make(chan []byte, 64),
        addrCh: make(chan net.Addr, 64),
        laddr:  laddr,
    }
}

func (c *fakePacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
    data, ok := <-c.dataCh
    if !ok {
        return 0, nil, io.EOF
    }
    n = copy(b, data)
    addr = <-c.addrCh
    return
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
    data := make([]byte, len(b))
    copy(data, b)
    c.dataCh <- data
    c.addrCh <- addr
    return len(b), nil
}

func (c *fakePacketConn) Close() error {
    c.closeMu.Lock()
    defer c.closeMu.Unlock()
    if !c.closed {
        c.closed = true
        close(c.dataCh)
        close(c.addrCh)
    }
    return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return c.laddr }

func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------------------
// fakeObserver — channel-based observer
// ---------------------------------------------------------------------------

type fakeObserver struct {
    eventsCh chan []observer.Event
    errFunc  func() error
}

func newFakeObserver(buffer int) *fakeObserver {
    return &fakeObserver{
        eventsCh: make(chan []observer.Event, buffer),
    }
}

func (o *fakeObserver) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
    if o.errFunc != nil {
        if err := o.errFunc(); err != nil {
            return err
        }
    }
    select {
    case o.eventsCh <- events:
    default:
    }
    return nil
}

func (o *fakeObserver) Events() <-chan []observer.Event { return o.eventsCh }

// ---------------------------------------------------------------------------
// mockAuther
// ---------------------------------------------------------------------------

type mockAuther struct {
    authenticateFn func(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool)
}

func (a *mockAuther) Authenticate(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
    if a.authenticateFn != nil {
        return a.authenticateFn(ctx, user, pass, opts...)
    }
    return "", false
}

// ---------------------------------------------------------------------------
// mockRateLimiter
// ---------------------------------------------------------------------------

type mockRateLimiter struct {
    allowFn func(n int) bool
}

func (l *mockRateLimiter) Allow(n int) bool {
    if l.allowFn != nil {
        return l.allowFn(n)
    }
    return true
}
func (l *mockRateLimiter) Limit() float64 { return 1 }
func (l *mockRateLimiter) Wait(ctx context.Context) error { return nil }

type mockRateLimiterContainer struct {
    limiterFn func(key string) rate.Limiter
}

func (c *mockRateLimiterContainer) Limiter(key string) rate.Limiter {
    if c.limiterFn != nil {
        return c.limiterFn(key)
    }
    return nil
}

// ---------------------------------------------------------------------------
// mockTrafficLimiter
// ---------------------------------------------------------------------------

type mockTrafficLimiter struct{}

func (l *mockTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
    return nil
}
func (l *mockTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
    return nil
}

// ---------------------------------------------------------------------------
// mockRouter — implements core/router.Router
// ---------------------------------------------------------------------------

type mockRouter struct {
    getRouteFn func(ctx context.Context, dst string, opts ...router.Option) *router.Route
}

func (r *mockRouter) GetRoute(ctx context.Context, dst string, opts ...router.Option) *router.Route {
    if r.getRouteFn != nil {
        return r.getRouteFn(ctx, dst, opts...)
    }
    return nil
}

// ---------------------------------------------------------------------------
// mockSD
// ---------------------------------------------------------------------------

type mockSD struct {
    getFn       func(ctx context.Context, name string, opts ...sd.Option) ([]*sd.Service, error)
    registerFn  func(ctx context.Context, svc *sd.Service, opts ...sd.Option) error
    deregisterFn func(ctx context.Context, svc *sd.Service, opts ...sd.Option) error
    renewFn     func(ctx context.Context, svc *sd.Service, opts ...sd.Option) error
}

func (s *mockSD) Get(ctx context.Context, name string, opts ...sd.Option) ([]*sd.Service, error) {
    if s.getFn != nil {
        return s.getFn(ctx, name, opts...)
    }
    return nil, nil
}
func (s *mockSD) Register(ctx context.Context, svc *sd.Service, opts ...sd.Option) error {
    if s.registerFn != nil {
        return s.registerFn(ctx, svc, opts...)
    }
    return nil
}
func (s *mockSD) Deregister(ctx context.Context, svc *sd.Service, opts ...sd.Option) error {
    if s.deregisterFn != nil {
        return s.deregisterFn(ctx, svc, opts...)
    }
    return nil
}
func (s *mockSD) Renew(ctx context.Context, svc *sd.Service, opts ...sd.Option) error {
    if s.renewFn != nil {
        return s.renewFn(ctx, svc, opts...)
    }
    return nil
}

// ---------------------------------------------------------------------------
// mockIngress
// ---------------------------------------------------------------------------

type mockIngress struct {
    getRuleFn func(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule
}

func (ing *mockIngress) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
    if ing.getRuleFn != nil {
        return ing.getRuleFn(ctx, host, opts...)
    }
    return nil
}

// ---------------------------------------------------------------------------
// buildRelayAssociateRequest — serializes a relay association request
// ---------------------------------------------------------------------------

func buildRelayAssociateRequest(t testingT, address string, routerID relay.TunnelID, network string) []byte {
    t.Helper()
    req := relay.Request{
        Version: relay.Version1,
        Cmd:     relay.CmdAssociate,
    }

    if address != "" {
        af := &relay.AddrFeature{}
        if err := af.ParseFrom(address); err != nil {
            t.Fatal(err)
        }
        req.Features = append(req.Features, af)
    }

    req.Features = append(req.Features, &relay.TunnelFeature{ID: routerID})

    networkID := relay.NetworkIP
    switch network {
    case "ip", "ip4", "ip6":
        networkID = relay.NetworkIP
    }
    req.Features = append(req.Features, &relay.NetworkFeature{Network: networkID})

    var buf bytes.Buffer
    if _, err := req.WriteTo(&buf); err != nil {
        t.Fatal(err)
    }
    return buf.Bytes()
}

// ---------------------------------------------------------------------------
// readRelayResponse — deserializes relay.Response from bytes
// ---------------------------------------------------------------------------

func readRelayResponse(t testingT, data []byte) *relay.Response {
    t.Helper()
    resp := &relay.Response{}
    if _, err := resp.ReadFrom(bytes.NewReader(data)); err != nil {
        t.Fatalf("read relay response: %v", err)
    }
    return resp
}

// ---------------------------------------------------------------------------
// testingT interface
// ---------------------------------------------------------------------------

type testingT interface {
    Helper()
    Fatal(args ...any)
    Fatalf(format string, args ...any)
}

// ---------------------------------------------------------------------------
// Helper: build a minimal fake packet payload for handlePacket tests
// ---------------------------------------------------------------------------

// buildIPv4Packet creates a minimal valid IPv4 packet for testing.
func buildIPv4Packet(srcIP, dstIP string, payload []byte) []byte {
    // Minimal IPv4 header: 20 bytes, no options
    const headerLen = 20
    totalLen := headerLen + len(payload)
    pkt := make([]byte, totalLen)

    // Version (4) + IHL (5)
    pkt[0] = 0x45
    // Total Length
    pkt[2] = byte(totalLen >> 8)
    pkt[3] = byte(totalLen)
    // TTL
    pkt[8] = 64
    // Protocol: UDP (17)
    pkt[9] = 17
    // Source IP
    copy(pkt[12:16], net.ParseIP(srcIP).To4())
    // Destination IP
    copy(pkt[16:20], net.ParseIP(dstIP).To4())
    // Header checksum (simple one's complement sum)
    var sum uint32
    for i := 0; i < headerLen; i += 2 {
        sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
    }
    for sum>>16 > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    pkt[10] = byte(^sum >> 8)
    pkt[11] = byte(^sum & 0xFF)

    copy(pkt[headerLen:], payload)
    return pkt
}

// buildIPv6Packet creates a minimal valid IPv6 packet for testing.
func buildIPv6Packet(srcIP, dstIP string, payload []byte) []byte {
    pkt := make([]byte, 40+len(payload))
    // Version (6) + Traffic Class + Flow Label
    pkt[0] = 0x60
    // Payload Length
    pkt[4] = byte(len(payload) >> 8)
    pkt[5] = byte(len(payload))
    // Next Header: UDP (17)
    pkt[6] = 17
    // Hop Limit
    pkt[7] = 64
    // Source IP
    copy(pkt[8:24], net.ParseIP(srcIP).To16())
    // Destination IP
    copy(pkt[24:40], net.ParseIP(dstIP).To16())
    copy(pkt[40:], payload)
    return pkt
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /config/workspace/go-gost/x && go build ./handler/router/ && go vet ./handler/router/
```

- [ ] **Step 3: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/helpers_test.go
git commit -m "test(handler/router): add helpers_test.go with mocks and test infrastructure"
```

---

### Task 5: Write metadata_test.go

**Files:**
- Create: `handler/router/metadata_test.go`

- [ ] **Step 1: Write metadata_test.go**

```go
package router

import (
    "testing"
    "time"

    "github.com/go-gost/core/ingress"
    "github.com/go-gost/core/logger"
    "github.com/go-gost/core/sd"
    "github.com/go-gost/relay"
    "github.com/google/uuid"
)

func TestParseMetadata_Empty(t *testing.T) {
    h := &routerHandler{
        options: handler.Options{
            Logger: logger.Default(),
        },
    }
    if err := h.parseMetadata(testMD(nil)); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if h.md.readTimeout != 0 {
        t.Errorf("readTimeout = %v, want 0", h.md.readTimeout)
    }
    if h.md.bufferSize != defaultBufferSize {
        t.Errorf("bufferSize = %d, want %d", h.md.bufferSize, defaultBufferSize)
    }
    if h.md.entryPoint != "" {
        t.Errorf("entryPoint = %q, want empty", h.md.entryPoint)
    }
    if h.md.sdCacheExpiration != defaultCacheExpiration {
        t.Errorf("sdCacheExpiration = %v, want %v", h.md.sdCacheExpiration, defaultCacheExpiration)
    }
    if h.md.sdRenewInterval != defaultTTL {
        t.Errorf("sdRenewInterval = %v, want %v", h.md.sdRenewInterval, defaultTTL)
    }
    if h.md.observerPeriod != 5*time.Second {
        t.Errorf("observerPeriod = %v, want 5s", h.md.observerPeriod)
    }
}
```

Continue with:
- `TestParseMetadata_ReadTimeout` — sets `readTimeout: "10s"`
- `TestParseMetadata_BufferSize` — sets `router.bufferSize: 8192`
- `TestParseMetadata_BufferSize_Zero` — sets `router.bufferSize: 0`, expects default
- `TestParseMetadata_EntryPoint` — sets `entrypoint: ":8080"`
- `TestParseMetadata_Ingress` — note: ingress lookup uses registry, test with empty (registered name)
- `TestParseMetadata_SD` — note: sd lookup uses registry, test with empty
- `TestParseMetadata_SDCacheExpiration` — sets `sd.cache.expiration: "30s"`
- `TestParseMetadata_SDRenewInterval` — sets `sd.renewInterval: "30s"`
- `TestParseMetadata_SDRenewInterval_TooSmall` — sets `sd.renewInterval: "100ms"`, expects clamps to defaultTTL
- `TestParseMetadata_RouterCache` — sets `router.cache: true`, `router.cache.expiration: "30s"`
- `TestParseMetadata_ObserverPeriod` — sets `observePeriod: "10s"`
- `TestParseMetadata_ObserverPeriod_TooSmall` — sets `observePeriod: "100ms"`, expects clamps to 1s
- `TestParseMetadata_ObserverResetTraffic` — sets `observer.resetTraffic: true`
- `TestParseMetadata_LimiterRefresh` — sets `limiter.refreshInterval: "30s"`, `limiter.cleanupInterval: "60s"`

- [ ] **Step 2: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestParseMetadata -v
```

- [ ] **Step 3: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/metadata_test.go
git commit -m "test(handler/router): add metadata_test.go for parseMetadata"
```

---

### Task 6: Write router_test.go

**Files:**
- Create: `handler/router/router_test.go`

- [ ] **Step 1: Write tests for Connector**

```go
package router

import (
    "bytes"
    "errors"
    "testing"

    "github.com/go-gost/relay"
    "github.com/google/uuid"
)

func TestNewConnector_Minimal(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    cid := relay.NewConnectorID([]byte("abcdef0123456789"))
    c := NewConnector(rid, cid, "example.com", nil, nil)
    if c == nil {
        t.Fatal("connector is nil")
    }
    if !c.ID().Equal(cid) {
        t.Errorf("ID = %v, want %v", c.ID(), cid)
    }
    if w := c.Writer(); w != nil {
        t.Errorf("Writer = %v, want nil", w)
    }
}

func TestNewConnector_WithOpts(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    cid := relay.NewConnectorID([]byte("abcdef0123456789"))
    var buf bytes.Buffer
    c := NewConnector(rid, cid, "example.com", &buf, &ConnectorOptions{})
    if c == nil {
        t.Fatal("connector is nil")
    }
    n, err := c.Writer().Write([]byte("hello"))
    if err != nil {
        t.Fatalf("write: %v", err)
    }
    if n != 5 {
        t.Errorf("n = %d, want 5", n)
    }
    if buf.String() != "hello" {
        t.Errorf("buf = %q, want hello", buf.String())
    }
}

func TestConnector_Close_NilWriter(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    cid := relay.NewConnectorID([]byte("abcdef0123456789"))
    c := NewConnector(rid, cid, "example.com", nil, nil)
    if err := c.Close(); err != nil {
        t.Fatalf("Close: %v", err)
    }
}

func TestConnector_Close_Writer(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    cid := relay.NewConnectorID([]byte("abcdef0123456789"))
    closed := false
    c := NewConnector(rid, cid, "example.com", &closeWriter{closeFn: func() error { closed = true; return nil }}, nil)
    if err := c.Close(); err != nil {
        t.Fatalf("Close: %v", err)
    }
    if !closed {
        t.Error("writer was not closed")
    }
}

type closeWriter struct {
    closeFn func() error
}

func (w *closeWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *closeWriter) Close() error {
    if w.closeFn != nil {
        return w.closeFn()
    }
    return nil
}
```

- [ ] **Step 2: Write tests for Router**

Tests:
- `TestRouter_AddConnector_Nil` — nil connector is skipped
- `TestRouter_AddConnector_GetConnector_Single` — add one, get back same
- `TestRouter_AddConnector_GetConnector_Multiple` — add two for same host, Get returns non-nil
- `TestRouter_GetConnector_EmptyHost` — empty host returns nil
- `TestRouter_GetConnector_Weighted` — multiple connectors with different weights
- `TestRouter_GetConnector_MaxWeight` — MaxWeight connector takes priority
- `TestRouter_DelConnector` — add two, delete one, remaining still accessible
- `TestRouter_DelConnector_NoMatch` — delete non-existent cid is no-op
- `TestRouter_DelConnector_WrongHost` — delete cid from wrong host is no-op
- `TestRouter_Close` — close clears connectors
- `TestRouter_Close_Double` — double close is safe

```go
func TestRouter_AddGetConnector(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    r := NewRouter("node1", rid)
    if r == nil {
        t.Fatal("router is nil")
    }
    if !r.ID().Equal(rid) {
        t.Errorf("ID = %v, want %v", r.ID(), rid)
    }

    cid := relay.NewConnectorID([]byte("abcdef0123456789"))
    c := NewConnector(rid, cid, "host1", nil, nil)
    r.AddConnector(c)

    got := r.GetConnector("host1")
    if got == nil {
        t.Fatal("GetConnector returned nil")
    }
    if !got.ID().Equal(cid) {
        t.Errorf("ID = %v, want %v", got.ID(), cid)
    }
}

func TestRouter_AddConnector_Nil(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    r := NewRouter("node1", rid)
    r.AddConnector(nil) // should not panic
}

func TestRouter_DelConnector(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    r := NewRouter("node1", rid)

    cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
    cid2 := relay.NewConnectorID([]byte("bbbbbbbbbbbbbbbb"))
    r.AddConnector(NewConnector(rid, cid1, "host1", nil, nil))
    r.AddConnector(NewConnector(rid, cid2, "host1", nil, nil))

    r.DelConnector("host1", cid1)
    got := r.GetConnector("host1")
    if got == nil {
        t.Fatal("GetConnector returned nil after delete")
    }
    if !got.ID().Equal(cid2) {
        t.Errorf("remaining connector = %v, want %v", got.ID(), cid2)
    }
}

func TestRouter_DelConnector_NoBreak(t *testing.T) {
    // Regression test: adding 3 connectors and deleting the first
    // should not affect the remaining ones.
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    r := NewRouter("node1", rid)

    ids := make([]relay.ConnectorID, 3)
    for i := range ids {
        uid := uuid.New()
        ids[i] = relay.NewConnectorID(uid[:])
        r.AddConnector(NewConnector(rid, ids[i], "host1", nil, nil))
    }

    // Delete the first connector
    r.DelConnector("host1", ids[0])

    // The remaining two should still be accessible
    got := r.GetConnector("host1")
    if got == nil {
        t.Fatal("GetConnector returned nil")
    }
}

func TestRouter_Close(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    r := NewRouter("node1", rid)
    r.AddConnector(NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "host1", nil, nil))

    if err := r.Close(); err != nil {
        t.Fatalf("Close: %v", err)
    }
    // After close, GetConnector should return nil (connectors cleared)
    if got := r.GetConnector("host1"); got != nil {
        t.Error("GetConnector returned non-nil after Close")
    }
}

func TestRouter_Close_Double(t *testing.T) {
    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    r := NewRouter("node1", rid)
    r.Close()
    r.Close() // second close should not panic
}
```

- [ ] **Step 3: Write tests for ConnectorPool**

Tests:
- `TestConnectorPool_NilSafe_Get` — nil pool Get returns nil
- `TestConnectorPool_NilSafe_Del` — nil pool Del is no-op
- `TestConnectorPool_NilSafe_Close` — nil pool Close returns nil
- `TestConnectorPool_AddGet` — add connector, get it back
- `TestConnectorPool_AddGet_NewRouter` — different rid creates different router
- `TestConnectorPool_Del` — add then delete
- `TestConnectorPool_Close` — close clears routers

- [ ] **Step 4: Write tests for parseRouterID**

Tests:
- `TestParseRouterID_Empty` — returns zero value
- `TestParseRouterID_ValidUUID` — parses correctly
- `TestParseRouterID_Invalid` — invalid UUID returns zero value (no error)

- [ ] **Step 5: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestRouter\|TestNewConnector\|TestConnector\|TestConnectorPool\|TestParseRouterID -v
```

- [ ] **Step 6: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/router_test.go
git commit -m "test(handler/router): add router_test.go (Connector, Router, ConnectorPool, parseRouterID)"
```

---

### Task 7: Write conn_test.go

**Files:**
- Create: `handler/router/conn_test.go`

- [ ] **Step 1: Write packetConn tests**

Tests:
- `TestPacketConn_ReadWrite` — write then read back
- `TestPacketConn_Read_Empty` — length 0 packet
- `TestPacketConn_Write_ExceedsMaxUint16` — error
- `TestPacketConn_Read_BufferSmaller` — read truncated
- `TestPacketConn_ReadWrite_Roundtrip` — full round-trip via pipeConn

- [ ] **Step 2: Write lockWriter tests**

Tests:
- `TestLockWriter_Write` — basic write
- `TestLockWriter_Concurrent` — concurrent writes (with -race check)
- `TestLockWriter_Close_Closer` — writer implements io.Closer
- `TestLockWriter_Close_NonCloser` — writer does not implement io.Closer
- `TestLockWriter_Close_Multiple` — double close safe

- [ ] **Step 3: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestPacketConn\|TestLockWriter -v
```

- [ ] **Step 4: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/conn_test.go
git commit -m "test(handler/router): add conn_test.go (packetConn, lockWriter)"
```

---

### Task 8: Write observe_test.go

**Files:**
- Create: `handler/router/observe_test.go`

- [ ] **Step 1: Write checkRateLimit tests**

```go
package router

import (
    "context"
    "net"
    "testing"
    "time"

    "github.com/go-gost/core/handler"
    "github.com/go-gost/core/limiter/rate"
    "github.com/go-gost/core/logger"
)

func TestCheckRateLimit_NilLimiter(t *testing.T) {
    h := &routerHandler{
        options: handler.Options{
            RateLimiter: nil,
            Logger:      logger.Default(),
        },
    }
    addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
    if !h.checkRateLimit(addr) {
        t.Error("checkRateLimit returned false, want true")
    }
}

func TestCheckRateLimit_Allowed(t *testing.T) {
    h := &routerHandler{
        options: handler.Options{
            RateLimiter: &mockRateLimiterContainer{
                limiterFn: func(key string) rate.Limiter {
                    return &mockRateLimiter{
                        allowFn: func(n int) bool { return true },
                    }
                },
            },
            Logger: logger.Default(),
        },
    }
    addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
    if !h.checkRateLimit(addr) {
        t.Error("checkRateLimit returned false, want true")
    }
}

func TestCheckRateLimit_Denied(t *testing.T) {
    h := &routerHandler{
        options: handler.Options{
            RateLimiter: &mockRateLimiterContainer{
                limiterFn: func(key string) rate.Limiter {
                    return &mockRateLimiter{
                        allowFn: func(n int) bool { return false },
                    }
                },
            },
            Logger: logger.Default(),
        },
    }
    addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
    if h.checkRateLimit(addr) {
        t.Error("checkRateLimit returned true, want false")
    }
}
```

- [ ] **Step 2: Write observeStats tests**

Tests:
- `TestObserveStats_NilObserver` — observer is nil, goroutine exits immediately
- `TestObserveStats_NormalCycle` — events sent on ticker, received on channel
- `TestObserveStats_ObserverError_Retry` — observer returns error, events buffered and retried
- `TestObserveStats_ContextCancel` — cancel context, goroutine exits

These tests require constructing a `routerHandler` with `newInitdHandler`. The handler_test.go will define `newInitdHandler`, so this test needs to either:
(a) Define its own helper, or
(b) Be written after handler_test.go

Write as a separate test file that defines its own `newHandlerForObserve` helper:

```go
func newHandlerWithObserver(t *testing.T, observer *fakeObserver) *routerHandler {
    t.Helper()
    h := NewHandler(
        handler.LoggerOption(&testLogger{}),
        handler.ObserverOption(observer),
        handler.ServiceOption("test-svc"),
    ).(*routerHandler)
    h.parseMetadata(testMD(map[string]any{
        "observePeriod": "100ms",
    }))
    return h
}
```

- [ ] **Step 3: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestCheckRateLimit\|TestObserveStats -v
```

- [ ] **Step 4: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/observe_test.go
git commit -m "test(handler/router): add observe_test.go (checkRateLimit, observeStats)"
```

---

### Task 9: Write handler_test.go

**Files:**
- Create: `handler/router/handler_test.go`

- [ ] **Step 1: Write newInitdHandler helper**

```go
package router

import (
    "bytes"
    "context"
    "errors"
    "net"
    "testing"
    "time"

    "github.com/go-gost/core/auth"
    "github.com/go-gost/core/handler"
    "github.com/go-gost/core/limiter/rate"
    "github.com/go-gost/core/logger"
    "github.com/go-gost/relay"
    "github.com/google/uuid"
)

func newInitdHandler(t *testing.T, opts ...handler.Option) *routerHandler {
    t.Helper()
    h := NewHandler(append([]handler.Option{
        handler.LoggerOption(&testLogger{}),
    }, opts...)...).(*routerHandler)
    h.parseMetadata(testMD(nil))
    h.pool = NewConnectorPool("test")
    ctx, cancel := context.WithCancel(context.Background())
    h.cancel = cancel
    return h
}
```

Note: `Init` calls `net.ListenPacket` if `entryPoint` is set, which can fail in tests. The `newInitdHandler` skips `Init` and directly initializes the needed fields. For tests that test `Init` itself, call `Init` directly.

- [ ] **Step 2: Write NewHandler tests**

- `TestNewHandler_Minimal` — h is not nil, type assertion succeeds
- `TestNewHandler_WithOptions` — Logger, Service options are set

- [ ] **Step 3: Write Init tests**

- `TestInit_Minimal` — id is set, pool is created, cancel is set
- `TestInit_WithObserver` — stats is created, observe goroutine runs
- `TestInit_WithLimiter` — limiter is created

- [ ] **Step 4: Write Handle tests**

For Handle tests, we need to send relay requests over a connection:

- `TestHandle_BadVersion` — send request with wrong version, expect ErrBadVersion
- `TestHandle_UnknownCmd` — send request with unsupported cmd, expect ErrUnknownCmd
- `TestHandle_RateLimit` — rate limiter denies, expect ErrRateLimit
- `TestHandle_AuthSuccess` — send request with auth, auther validates, success
- `TestHandle_AuthFailure` — send request with auth, auther rejects, expect ErrUnauthorized
- `TestHandle_AssociateValid` — send valid associate request, expect OK response

- [ ] **Step 5: Write Close tests**

- `TestClose` — normal close
- `TestClose_Double` — double close safe
- `TestClose_NoEntrypoint` — close when epConn is nil

- [ ] **Step 6: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestNewHandler\|TestInit\|TestHandle\|TestClose -v
```

- [ ] **Step 7: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/handler_test.go
git commit -m "test(handler/router): add handler_test.go (NewHandler, Init, Handle, Close)"
```

---

### Task 10: Write associate_test.go

**Files:**
- Create: `handler/router/associate_test.go`

This is the largest test file. It tests handleAssociate, handlePacket, getRoute, getAddrforRoute, and sdRenew.

- [ ] **Step 1: Write handleAssociate tests**

These tests use a pipe pair: one end goes to handleAssociate, the other end is the test client.

```go
func TestHandleAssociate_NoIngress(t *testing.T) {
    client, server := newPipePair()
    defer client.Close()
    defer server.Close()

    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    h := newInitdHandler(t)
    h.md.ingress = nil

    errCh := make(chan error, 1)
    go func() {
        errCh <- h.handleAssociate(context.Background(), server, "ip", "10.0.0.1", rid, &testLogger{})
    }()

    // Client sends associate request
    req := buildRelayAssociateRequest(t, "10.0.0.1:0", rid, "ip")
    client.Write(req)

    // Read response
    respBuf := make([]byte, 1024)
    n, err := client.Read(respBuf)
    if err != nil {
        t.Fatalf("read response: %v", err)
    }

    resp := readRelayResponse(t, respBuf[:n])
    if resp.Status != relay.StatusOK {
        t.Errorf("status = %d, want %d", resp.Status, relay.StatusOK)
    }
}
```

Additional tests:
- `TestHandleAssociate_IngressMatch` — ingress has matching rule → success
- `TestHandleAssociate_IngressMismatch` — ingress rule points to different routerID → StatusHostUnreachable
- `TestHandleAssociate_WithSD` — SD registration is called
- `TestHandleAssociate_ConnectorCleanup` — connector added in pool, removed on exit

- [ ] **Step 2: Write handlePacket tests**

```go
func TestHandlePacket_IPv4_ConnectorForward(t *testing.T) {
    var buf bytes.Buffer
    c := NewConnector(
        relay.NewTunnelID([]byte("0123456789abcdef")),
        relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")),
        "10.0.0.1", &buf, nil,
    )

    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    h := newInitdHandler(t)
    h.pool.Add(rid, c)
    h.md.routerCacheEnabled = false

    pkt := buildIPv4Packet("10.0.0.2", "10.0.0.1", []byte("hello"))
    err := h.handlePacket(context.Background(), pkt, rid, &testLogger{})
    if err != nil {
        t.Fatalf("handlePacket: %v", err)
    }

    if buf.Len() == 0 {
        t.Error("no data written to connector")
    }
}
```

Additional tests:
- `TestHandlePacket_IPv6_ConnectorForward` — IPv6 packet forwarded to connector
- `TestHandlePacket_Unknown` — unknown packet type returns error
- `TestHandlePacket_NoRoute` — no route to destination returns error
- `TestHandlePacket_EntrypointForward` — connector not found, sent via epConn

- [ ] **Step 3: Write getRoute tests**

```go
func TestGetRoute_CacheHit(t *testing.T) {
    h := newInitdHandler(t)
    h.md.routerCacheEnabled = true
    h.md.routerCacheExpiration = time.Minute
    h.routeCache.Set("10.0.0.1", cache.NewItem(&router.Route{
        Dst: "10.0.0.0/24",
        Gateway: "10.0.0.254",
    }, time.Minute))

    route := h.getRoute(context.Background(), "test-rid", "10.0.0.1")
    if route == nil {
        t.Fatal("getRoute returned nil")
    }
    if route.Gateway != "10.0.0.254" {
        t.Errorf("gateway = %s, want 10.0.0.254", route.Gateway)
    }
}
```

Additional tests:
- `TestGetRoute_CacheMiss_Registry` — cache miss, looks up via registry
- `TestGetRoute_Fallback` — no registry router, uses fallback
- `TestGetRoute_CacheDisabled` — cache disabled, always lookup

- [ ] **Step 4: Write getAddrforRoute tests**

- `TestGetAddrforRoute_NilSD` — sd is nil, returns nil
- `TestGetAddrforRoute_CacheHit` — cached address returned
- `TestGetAddrforRoute_SDLookup` — cache miss, looks up via SD

- [ ] **Step 5: Write sdRenew tests**

- `TestSdRenew_Normal` — ticker fires, Renew called
- `TestSdRenew_Cancel` — context cancelled, goroutine exits

- [ ] **Step 6: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestHandleAssociate\|TestHandlePacket\|TestGetRoute\|TestGetAddrforRoute\|TestSdRenew -v
```

- [ ] **Step 7: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/associate_test.go
git commit -m "test(handler/router): add associate_test.go (handleAssociate, handlePacket, getRoute, getAddrforRoute, sdRenew)"
```

---

### Task 11: Write entrypoint_test.go

**Files:**
- Create: `handler/router/entrypoint_test.go`

- [ ] **Step 1: Write handleEntrypoint tests**

```go
package router

import (
    "testing"
    "time"

    "github.com/go-gost/relay"
)

func TestHandleEntrypoint_ForwardsToConnector(t *testing.T) {
    laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
    fpc := newFakePacketConn(laddr)

    rid := relay.NewTunnelID([]byte("0123456789abcdef"))
    cid := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))

    var connBuf bytes.Buffer
    c := NewConnector(rid, cid, "10.0.0.1", LockWriter(&connBuf), nil)

    h := newInitdHandler(t)
    h.epConn = fpc
    h.pool.Add(rid, c)

    errCh := make(chan error, 1)
    go func() {
        errCh <- h.handleEntrypoint(&testLogger{})
    }()

    // Build relay request + packet
    req := relay.Request{
        Version: relay.Version1,
        Cmd:     relay.CmdAssociate,
        Features: []relay.Feature{
            &relay.TunnelFeature{ID: rid},
            &relay.AddrFeature{
                AType: relay.AddrDomain,
                Host:  "10.0.0.1",
            },
        },
    }
    var buf bytes.Buffer
    req.WriteTo(&buf)
    buf.Write([]byte("packet-data"))

    fpc.dataCh <- buf.Bytes()
    fpc.addrCh <- laddr

    // Give the goroutine time to process
    time.Sleep(100 * time.Millisecond)

    if connBuf.Len() == 0 {
        t.Error("no data forwarded to connector")
    }
    if !bytes.Contains(connBuf.Bytes(), []byte("packet-data")) {
        t.Errorf("connector data = %q, want containing packet-data", connBuf.Bytes())
    }

    // Cleanup
    fpc.Close()
}
```

Additional tests:
- `TestHandleEntrypoint_NonAssociateCmd` — cmd is not Associate, packet is skipped
- `TestHandleEntrypoint_NoMatchingConnector` — no connector for gateway, packet dropped silently
- `TestHandleEntrypoint_ReadError` — ReadFrom returns error, goroutine exits

- [ ] **Step 2: Run tests**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race ./handler/router/ -run TestHandleEntrypoint -v
```

- [ ] **Step 3: Commit**

```bash
cd /config/workspace/go-gost/x && git add handler/router/entrypoint_test.go
git commit -m "test(handler/router): add entrypoint_test.go (handleEntrypoint)"
```

---

### Task 12: Final verification and full suite run

- [ ] **Step 1: Run all tests with race detector**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race -count=1 ./handler/router/ -v 2>&1
```

All tests must pass with no race warnings.

- [ ] **Step 2: Check build and vet**

```bash
cd /config/workspace/go-gost/x && go build ./handler/router/ && go vet ./handler/router/
```

- [ ] **Step 3: Run coverage**

```bash
cd /config/workspace/go-gost/x && CGO_ENABLED=1 go test -race -count=1 -coverprofile=/tmp/router-cover.out ./handler/router/ && go tool cover -func=/tmp/router-cover.out
```

- [ ] **Step 4: Commit any remaining changes**

```bash
cd /config/workspace/go-gost/x && git add -A && git status
```