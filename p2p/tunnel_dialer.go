// Package p2p adapts any dialer to run on top of a tunnel supplied by a p2p
// plugin. The inner dialer's base connection (options.Dialer) is replaced
// with "open a tunnel to the peer, dial the returned local endpoint". The
// peer-facing protocol stays owned by the inner dialer — p2p only supplies
// the tunnel base.
package p2p

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/metadata"
)

// rpcTimeout caps each control RPC (OpenTunnel/CloseTunnel) with a fresh
// context so a wedged plugin cannot stall a dial or leak a finalizer.
const rpcTimeout = 3 * time.Second

// TunnelProvider opens and closes tunnels to a peer. It is the wrapper's
// only contact with the p2p plugin; peer and endpoint are opaque strings.
type TunnelProvider interface {
	OpenTunnel(ctx context.Context, peer string) (id, endpoint string, err error)
	CloseTunnel(ctx context.Context, id string) error
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
// "inner dials one plain TCP stream via options.Dialer and uses it as its
// base" (mux inners dial it once per session and multiplex streams over it)
// — kcp/udp/quic bases are datagram conns, http2 probes and destroys
// tunnels. Fail closed: new dialers are unsupported until verified.
func SupportedDialer(name string) bool {
	switch name {
	case "tcp", "tls", "ws", "mtcp", "mtls", "mws":
		return true
	default:
		return false
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
		// The tunnel is unusable: close it and fail closed.
		if id := base.tunnelID(); id != "" {
			cctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
			defer cancel()
			d.provider.CloseTunnel(cctx, id)
		}
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

// tunnelBaseDialer lazily opens a tunnel on first use, then dials the tunnel
// endpoint and wraps the resulting conn with tunnel teardown. If the inner
// dialer never dials its base (mux session cache hit), no tunnel is opened.
type tunnelBaseDialer struct {
	peer string
	pr   TunnelProvider

	mu       sync.Mutex
	id       string
	endpoint string
}

// tunnelID returns the opened tunnel's id, or "" if none was opened.
func (d *tunnelBaseDialer) tunnelID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.id
}

func (d *tunnelBaseDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// Only the control RPC is time-capped; the endpoint dial runs on the
	// caller's ctx so a slow path to the peer isn't killed by this budget.
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.endpoint == "" {
		octx, cancel := context.WithTimeout(ctx, rpcTimeout)
		defer cancel()
		id, endpoint, err := d.pr.OpenTunnel(octx, d.peer)
		if err != nil {
			return nil, err
		}
		d.id, d.endpoint = id, endpoint
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.endpoint)
	if err != nil {
		// The tunnel is unusable: release it and forget it, so a retry
		// on the same base dialer opens a fresh one.
		cctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
		defer cancel()
		d.pr.CloseTunnel(cctx, d.id)
		d.id, d.endpoint = "", ""
		return nil, err
	}
	return &tunnelConn{Conn: conn, id: d.id, pr: d.pr, onClosed: func() {
		// The inner may close the conn before this base dialer ever sees an
		// error; clear the state so tunnelDialer's fail path doesn't issue a
		// second CloseTunnel.
		d.mu.Lock()
		d.id, d.endpoint = "", ""
		d.mu.Unlock()
	}}, nil
}

// tunnelConn is the tunnel handle: closing it closes the underlying conn and
// releases the tunnel (CloseTunnel) exactly once.
type tunnelConn struct {
	net.Conn
	id       string
	pr       TunnelProvider
	onClosed func()
	closeOne sync.Once
}

func (c *tunnelConn) Close() error {
	var err error
	c.closeOne.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
		defer cancel()
		err = c.pr.CloseTunnel(ctx, c.id)
		if cerr := c.Conn.Close(); err == nil {
			err = cerr
		}
		if c.onClosed != nil {
			c.onClosed()
		}
	})
	return err
}