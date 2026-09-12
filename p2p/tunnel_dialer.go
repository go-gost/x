// Package p2p adapts any dialer to run on top of a tunnel supplied by a p2p
// plugin. The inner dialer's base connection (options.Dialer) is replaced
// with the tunnel's data stream — a net.Conn carried over the GOST↔host gRPC
// connection. The peer-facing protocol stays owned by the inner dialer — p2p
// only supplies the tunnel base.
package p2p

import (
	"context"
	"net"
	"sync"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/metadata"
)

// TunnelProvider opens tunnels to a peer over the plugin control protocol.
// It is the wrapper's only contact with the p2p plugin; peer is an opaque
// string (the plugin defines its semantics). network is "tcp" or "udp" and
// selects the data stream's semantics: "udp" preserves datagram boundaries,
// so a datagram dialer gets a datagram conn instead of a byte stream.
type TunnelProvider interface {
	OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error)
	Close() error
}

// NewTunnelDialer wraps inner so that every Dial dials "through" a tunnel to
// the target peer, as if it were inner's plain base connection. The tunnel is
// opened lazily inside the base dialer: mux inners (mtcp etc.) hit their
// session cache without touching the base and must not leak an unused tunnel
// per dial. Inner protocol (tls/ws/mux...) stays untouched; its Handshake is
// forwarded by tunnelDialer so it triggers at Transport.Handshake.
// Fail-closed: any provider error aborts the dial.
func NewTunnelDialer(inner dialer.Dialer, pr TunnelProvider) dialer.Dialer {
	return &tunnelDialer{inner: inner, provider: pr}
}

// SupportedDialer reports whether a dialer type may be used as the inner
// protocol on top of a p2p tunnel. The wrapper's implicit contract is
// "inner dials one plain conn via options.Dialer and uses it as its base" —
// a byte stream for the stream dialers (mux inners dial it once per session
// and multiplex streams over it), a datagram stream for udp. kcp/quic
// bases, http2 probes and destroys tunnels. Fail closed: new dialers are
// unsupported until verified.
func SupportedDialer(name string) bool {
	switch name {
	case "tcp", "tls", "ws", "mtcp", "mtls", "mws", "udp":
		return true
	default:
		return false
	}
}

// tunnelNetwork normalizes a dialer network to the two the tunnel protocol
// defines, so a udp4/udp6 dialer still asks for a datagram stream.
func tunnelNetwork(network string) string {
	switch network {
	case "udp", "udp4", "udp6":
		return "udp"
	default:
		return "tcp"
	}
}

var _ dialer.Dialer = (*tunnelDialer)(nil)
var _ dialer.Handshaker = (*tunnelDialer)(nil)

type tunnelDialer struct {
	inner    dialer.Dialer
	provider TunnelProvider
}

func (d *tunnelDialer) Init(md metadata.Metadata) error {
	return d.inner.Init(md)
}

func (d *tunnelDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	// The tunnel is opened lazily by the base dialer: only when the inner
	// dialer actually dials its base. On a mux session cache hit the inner
	// never touches the base, and no tunnel (or control RPC) is spent.
	base := &tunnelBaseDialer{peer: addr, pr: d.provider}
	conn, err := d.inner.Dial(ctx, addr, append(opts, dialer.NetDialerDialOption(base))...)
	if err != nil {
		// The tunnel is unusable: close it and fail closed. closeTunnel is
		// nil-safe — OpenTunnelStream may have failed before any conn existed
		// (the host's pending GC then reclaims the record).
		base.closeTunnel()
		return nil, err
	}
	return conn, nil
}

// Handshake forwards to the inner dialer so its protocol handshake (TLS, ws
// upgrade, mux) still runs at Transport.Handshake. Inner without a
// Handshake (tcp) gets the conn back untouched.
func (d *tunnelDialer) Handshake(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
	if hs, ok := d.inner.(dialer.Handshaker); ok {
		return hs.Handshake(ctx, conn, opts...)
	}
	return conn, nil
}

// Multiplex delegates to the inner dialer when it multiplexes; the tunnel
// itself is one physical conn, so a muxing inner owns session lifetime.
func (d *tunnelDialer) Multiplex() bool {
	if m, ok := d.inner.(dialer.Multiplexer); ok {
		return m.Multiplex()
	}
	return false
}

// tunnelBaseDialer lazily opens a tunnel on first use and returns its data
// conn as the inner dialer's base. The conn's Close IS the tunnel teardown:
// the stream ending is the tunnel ending. If the inner dialer never dials its
// base (mux session cache hit), no tunnel is opened.
type tunnelBaseDialer struct {
	peer string
	pr   TunnelProvider

	mu   sync.Mutex
	conn net.Conn
}

// closeTunnel closes the opened conn, if any. Nil-safe: OpenTunnelStream can
// fail before any conn exists, and closing a nil net.Conn interface panics.
func (d *tunnelBaseDialer) closeTunnel() {
	d.mu.Lock()
	conn := d.conn
	d.conn = nil
	d.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (d *tunnelBaseDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// Only the control RPC is time-capped (inside OpenTunnelStream); the
	// stream runs on its own context so the conn outlives this dial.
	network = tunnelNetwork(network)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		conn, err := d.pr.OpenTunnelStream(ctx, network, d.peer)
		if err != nil {
			return nil, err
		}
		d.conn = conn
	}
	return d.conn, nil
}
