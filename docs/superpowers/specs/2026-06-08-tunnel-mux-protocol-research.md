# Tunnel Handler Multiplexing Protocol Research

**Date:** 2026-06-08
**Scope:** Investigate alternatives to SMUX for the tunnel handler's stream multiplexing, and assess feasibility of making the mux layer pluggable.

## Current State

- **Package:** `internal/util/mux/mux.go`
- **Library:** `github.com/xtaci/smux` v1.5.31
- **Default protocol version:** v1 (no per-stream flow control)
- **Consumers:** tunnel handler (bind/connect), relay connector, SOCKS5 connector, SSH dialer
- **Session surface:** `GetConn()`, `Accept()`, `Close()`, `IsClosed()`, `NumStreams()`

---

## 1. Protocol Comparison

### 1.1 SMUX v1 (current default)

- **Author:** xtaci (same as kcp-go)
- **Wire header:** 8 bytes (VER + CMD + LEN + SID)
- **Flow control:** None — sender pushes data without receiver feedback
- **Memory model:** Session-wide shared receive buffer; bounded overall memory
- **Keepalive:** NOP frames, configurable interval; known stability issues ([Issue #67](https://github.com/xtaci/smux/issues/67))
- **Throughput:** ~2247 MB/s single-stream (benchmark below)
- **Overhead vs raw TCP:** ~2.3x (5124 MB/s raw → 2247 MB/s muxed)
- **Allocations:** 1208 B/op, 19 allocs/op per stream operation

**Verdict:** Minimal overhead, but v1 lacks flow control — a single fast sender can starve other streams.

### 1.2 SMUX v2

- **Wire header:** Same 8 bytes, adds `cmdUPD` (window update)
- **Flow control:** Per-stream sliding window via `cmdUPD` frames — receiver sends consumed bytes + available window
- **Memory model:** Same session-wide buffer as v1, plus per-stream window tracking
- **Backpressure:** Stream-level — sender stalls when window is exhausted
- **Upgrade path:** Zero code change — just set `Version: 2` in config

**Verdict:** Strictly better than v1 for multi-stream workloads. Fair bandwidth distribution without sacrificing the session-wide memory model. **Recommended as immediate upgrade.**

### 1.3 Yamux (hashicorp/yamux)

- **Author:** HashiCorp; also forked by libp2p as go-yamux/v2
- **Wire header:** 12 bytes (Version + Type + Flags + StreamID + Length)
- **Flow control:** Window-based per-stream; default 256 KB window
- **Memory model:** Per-stream buffer (not shared)
- **Throughput:** ~24-28 Mbps per stream ([Issue #24](https://github.com/hashicorp/yamux/issues/24)) — limited by conservative window updates falling back to "safe speed"
- **Stream limit:** Hardcoded upper bound ([Issue #7](https://github.com/hashicorp/yamux/issues/7))
- **Backpressure:** On data streams only, NOT on stream open operations
- **API:** Implements `net.Conn` / `net.Listener` natively
- **Maintenance:** Low activity / stable; updated to Go 1.23
- **Ecosystem:** Used in HashiCorp products (Consul, Nomad), libp2p; sing-box defaults to yamux

**Verdict:** Wider ecosystem adoption than SMUX, but throughput-limited by window flow control. SMUX v2 has comparable flow control with better performance for proxy/tunnel workloads. Not a compelling upgrade over SMUX v2, but worth offering as a pluggable alternative.

### 1.4 QUIC Streams (quic-go)

- **Package:** `github.com/quic-go/quic-go` v0.59.1 (already a GOST dependency)
- **Multiplexing:** Native — streams are a first-class protocol primitive
- **Wire overhead:** QUIC frames (variable, typically 2-8 bytes per frame header)
- **Flow control:** Per-stream AND per-connection, protocol-level enforcement
- **Head-of-line blocking:** Eliminated — each stream is independent
- **Encryption:** Mandatory TLS 1.3 (built-in)
- **Connection setup:** 0-RTT possible; eliminates TCP+TLS handshake latency
- **Transport:** UDP (userspace)
- **CPU overhead:** 2x-4x higher per byte vs raw TCP ([Fastly benchmark](https://www.fastly.com/blog/measuring-quic-vs-tcp-computational-efficiency), [HN discussion](https://news.ycombinator.com/item?id=19476439))
- **Loss performance:** Significantly better than TCP at >5% packet loss
- **Equivalent to:** `kcp-go + smux` per [Turbo Tunnel evaluation](https://github.com/net4people/bbs/issues/14)

**Verdict:** Strongest technical alternative for new deployments, but NOT a mux-layer concern. QUIC multiplexes at the transport layer and requires UDP. GOST already handles QUIC at the listener/dialer level (`listener/http3/`, `dialer/http3/`). Not a candidate for the `internal/util/mux/` plugin interface.

### 1.5 HTTP/2 Streams (golang.org/x/net/http2)

- **Multiplexing:** Full HTTP/2 stream multiplexing with HPACK header compression
- **Wire overhead:** 9-byte frame header + HPACK-encoded headers per stream
- **Flow control:** Per-stream and per-connection
- **Overhead:** HTTP/2 framing + headers add significant overhead vs raw mux protocols
- **Use case:** sing-box uses this for `h2mux` mode

**Verdict:** Overkill for raw TCP proxy/tunneling. The HTTP/2 framing and header layers add unnecessary overhead. Better suited for HTTP-based proxying where header semantics are needed.

### 1.6 Mux.Cool (Xray/V2Ray)

- **Purpose:** Reduce TCP handshake latency for short-lived proxy connections
- **Throughput:** Officially documented as NOT designed for high throughput
- **Integration:** Tightly coupled to Xray/V2Ray proxy ecosystem

**Verdict:** Not a standalone mux library. Purpose-built for Xray ecosystem. Not applicable.

### 1.7 alecthomas/multiplex

- **Interface:** Multiplexes over any `io.ReadWriteCloser`
- **Approach:** Fragmentation-based fairness across channels
- **Maintenance:** Minimal activity

**Verdict:** General-purpose but not optimized for proxy/tunnel workloads. Insufficient battle-testing in high-throughput scenarios.

---

## 2. Benchmarks

### SMUX (from upstream README, macOS/amd64)

```
BenchmarkMSB-4            30000000       51.8 ns/op
BenchmarkAcceptClose-4       50000    36783 ns/op
BenchmarkConnSmux-4          30000    58335 ns/op  2246.88 MB/s   1208 B/op   19 allocs/op
BenchmarkConnTCP-4           50000    25579 ns/op  5124.04 MB/s      0 B/op    0 allocs/op
```

**Key finding:** SMUX achieves ~44% of raw TCP throughput (2247 vs 5124 MB/s). The overhead comes from frame allocation (~1208 B/op, 19 allocs/op) and the session-level coordination.

### Yamux (from [Issue #24](https://github.com/hashicorp/yamux/issues/24))

- ~24-28 Mbps per stream with 2 concurrent streams
- Limited by window flow control falling back to "safe speed"
- Per-stream window: 256 KB (configurable via `MaxStreamWindowSize`)

**Comparison:** SMUX achieves ~18 Gbps (2247 MB/s) single-stream on the same benchmark hardware. Yamux's ~24-28 Mbps is orders of magnitude lower. The difference is primarily due to Yamux's conservative window-based flow control vs SMUX's token-bucket approach. However, the Yamux benchmark is from a real-world multi-stream scenario, while SMUX's is single-stream — not directly comparable.

### QUIC (from [QUIC tunneling blog](https://mranv.pages.dev/posts/quic-tunneling-go-implementation/), [arXiv paper](https://arxiv.org/html/2504.10054v2))

- ~66% lower latency vs TCP-based tunneling
- ~70% higher throughput vs TCP in lossy/unstable networks
- CPU overhead: 2x-4x higher vs raw TCP (userspace UDP processing)
- At <1% packet loss: performance roughly equivalent to TCP
- At >5% packet loss: QUIC significantly outperforms TCP

### Summary Table

| Protocol | Single-stream throughput | Multi-stream fairness | CPU overhead | HOL blocking | Encryption | Transport |
|----------|------------------------|----------------------|-------------|-------------|------------|-----------|
| SMUX v1  | ~2247 MB/s (44% TCP)   | Poor (no flow control) | ~2.3x TCP  | Present     | None       | TCP       |
| SMUX v2  | ~2247 MB/s (44% TCP)   | Good (per-stream window) | ~2.3x TCP | Present     | None       | TCP       |
| Yamux    | ~24-28 Mbps/stream     | Fair (window-based)   | ~2-3x TCP   | Present     | None       | TCP       |
| QUIC     | Better at >5% loss     | Excellent (native)    | 2x-4x TCP   | Eliminated  | TLS 1.3    | UDP       |
| HTTP/2   | Good                   | Good (HTTP/2 flow ctrl) | Moderate  | Present     | TLS        | TCP       |

---

## 3. Config Integration: Making Mux Pluggable

### Current Architecture

The mux layer is a thin wrapper in `internal/util/mux/mux.go`:
- `Config` struct — SMUX-specific parameters
- `ClientSession(conn, cfg)` / `ServerSession(conn, cfg)` — factory functions
- `Session` struct — concrete type wrapping `*smux.Session`
- `streamConn` — wraps `*smux.Stream` as `net.Conn`

All consumers use `*mux.Session` (pointer to concrete struct):
- `handler/tunnel/bind.go`, `handler/tunnel/connect.go`
- `handler/relay/entrypoint.go`
- `connector/socks/v5/bind.go`, `connector/relay/bind.go`
- `dialer/ssh/dialer.go`, `dialer/sshd/dialer.go`

### Recommended Approach: Interface Extraction

Convert `mux.Session` from a concrete struct to an interface, keeping everything in `internal/util/mux/`:

```go
// Session is the interface for a multiplexed connection session.
type Session interface {
    GetConn() (net.Conn, error)   // Open stream (client)
    Accept() (net.Conn, error)    // Accept stream (server)
    Close() error
    IsClosed() bool
    NumStreams() int
}
```

Add `MuxType` to `Config`:

```go
type Config struct {
    MuxType string  // "smux" (default), "yamux"

    // SMUX fields (existing)
    Version int
    // ...

    // Yamux fields (new)
    MaxStreamWindowSize uint32
}
```

Factory functions dispatch on `MuxType`:

```go
func ClientSession(conn net.Conn, cfg *Config) (Session, error) {
    switch muxType(cfg) {
    case "yamux":
        return newYamuxClientSession(conn, cfg)
    default:
        return newSMUXClientSession(conn, cfg)
    }
}
```

Consumer changes: replace `*mux.Session` → `mux.Session` (interface value). Minimal mechanical change.

### YAML Config Surface

The mux config flows through metadata. Today it's parsed in `handler/tunnel/metadata.go`:

```go
// Current: tunnel handler metadata
type metadata struct {
    muxCfg *mux.Config
    // ...
}
```

With the pluggable design, users configure it via the service metadata:

```yaml
services:
  - name: tunnel-server
    handler:
      type: tunnel
      metadata:
        mux.type: yamux          # "smux" | "yamux"  (default: "smux")
        mux.version: 2           # SMUX protocol version (only for smux)
        mux.maxFrameSize: 32768
        mux.maxStreamWindow: 524288  # Yamux window size (only for yamux)
```

The existing `mdutil.GetString(md, "mux.type", "muxType")` pattern works naturally.

### What About QUIC?

QUIC is fundamentally different — it multiplexes at the transport layer, not over an existing TCP connection. It cannot be a drop-in alternative for the `internal/util/mux/` interface because:

1. QUIC requires UDP transport, not TCP
2. QUIC connections are created differently (not by upgrading an existing `net.Conn`)
3. QUIC streams already exist as first-class objects

QUIC-based multiplexing is better addressed as a separate listener/dialer pair (which GOST already has: `listener/http3/`, `dialer/http3/`, etc.), not as a mux plugin.

### Backward Compatibility

- Default `MuxType: ""` → `"smux"` — existing configs unchanged
- Default SMUX version stays at v1 (no behavior change for existing deployments)
- Users opt into v2 or yamux explicitly via metadata

### Candidates Worth Implementing

| Priority | Protocol | Rationale |
|----------|----------|-----------|
| 1 (immediate) | SMUX v2 | Zero-dependency upgrade, per-stream flow control, just change default version |
| 2 (high value) | Yamux | Broad ecosystem adoption (sing-box defaults to it), well-tested, different trade-off profile |
| 3 (future) | None of the others | QUIC is already handled at the listener/dialer level; HTTP/2 and Mux.Cool add unnecessary complexity |

---

## 4. Conclusions

1. **SMUX v2 should be the default.** Per-stream sliding window flow control is strictly better than v1 for multi-stream tunnel workloads. Zero code risk — same library, just `Version: 2`.

2. **Yamux is the most viable alternative** for users who want different flow control characteristics (window-based vs token-bucket). It's well-tested in production at HashiCorp and libp2p. The throughput concerns (24-28 Mbps/stream) may not apply to GOST's typical workload where streams are I/O-bound rather than CPU-bound.

3. **Making mux pluggable is straightforward.** The `Session` interface is only 5 methods. All 8 consumers just change `*mux.Session` → `mux.Session`. Config flows through existing metadata parsing. No new `core/` package or registry needed.

4. **QUIC is not a mux-layer concern.** It's already handled at the listener/dialer level in GOST. QUIC's native stream multiplexing is a transport-level feature, not something to bolt onto TCP connections.

5. **SMUX's keepalive issue ([#67](https://github.com/xtaci/smux/issues/67)) should be tracked.** If it causes production problems, Yamux becomes a more attractive fallback.

---

## Sources

- [xtaci/smux GitHub](https://github.com/xtaci/smux)
- [hashicorp/yamux GitHub](https://github.com/hashicorp/yamux)
- [Yamux Performance Issue #24](https://github.com/hashicorp/yamux/issues/24)
- [SMUX Keepalive Issue #67](https://github.com/xtaci/smux/issues/67)
- [quic-go Streams Docs](https://quic-go.net/docs/quic/streams/)
- [QUIC vs TCP (arXiv)](https://arxiv.org/html/2504.10054v2)
- [Turbo Tunnel Protocol Evaluation](https://github.com/net4people/bbs/issues/14)
- [QUIC Tunneling in Go](https://mranv.pages.dev/posts/quic-tunneling-go-implementation/)
- [Fastly: QUIC vs TCP Efficiency](https://www.fastly.com/blog/measuring-quic-vs-tcp-computational-efficiency)
- [sing-box Mux Config](https://sing-box.sagernet.org/configuration/shared/multiplex/)
