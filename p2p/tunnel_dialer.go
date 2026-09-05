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

// NewTunnelDialer wraps inner so that every Dial first opens a tunnel to the
// target peer, then lets inner dial "through" the tunnel as if it were its
// plain base connection. Inner protocol (tls/ws/mux...) stays untouched;
// its Handshake is forwarded by tunnelDialer so it triggers at
// Transport.Handshake. Fail-closed: any provider error aborts the dial.
func NewTunnelDialer(inner dialer.Dialer, pr TunnelProvider) dialer.Dialer {
	return &tunnelDialer{inner: inner, provider: pr}
}

// SupportedDialer reports whether a dialer type may be used as the inner
// protocol on top of a p2p tunnel. The wrapper's implicit contract is
// "inner dials one plain TCP stream via options.Dialer and uses it as its
// base" — kcp/udp/quic bases are datagram conns, http2 probes and destroys
// tunnels. Fail closed: new dialers are unsupported until verified.
func SupportedDialer(name string) bool {
	switch name {
	case "tcp":
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
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	// Only the control RPC is time-capped; the inner dial runs on the
	// caller's ctx so a slow path to the peer isn't killed by this budget.
	octx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	id, endpoint, err := d.provider.OpenTunnel(octx, addr)
	if err != nil {
		return nil, err
	}

	// Replace the inner dialer's base conn (options.Dialer, set by
	// Transport.Dial) with a dialer that connects the tunnel endpoint and
	// returns the tunnelConn unchanged — the inner dialer never sees that
	// its base is a tunnel.
	base := &tunnelBaseDialer{endpoint: endpoint, id: id, pr: d.provider}
	conn, err := d.inner.Dial(ctx, addr, append(opts, dialer.NetDialerDialOption(base))...)
	if err != nil {
		// The tunnel is unusable: close it and fail closed.
		cctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
		defer cancel()
		d.provider.CloseTunnel(cctx, id)
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

// tunnelBaseDialer dials the tunnel endpoint and wraps the resulting conn
// with tunnel teardown.
type tunnelBaseDialer struct {
	endpoint string
	id       string
	pr       TunnelProvider
}

func (d *tunnelBaseDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.endpoint)
	if err != nil {
		return nil, err
	}
	return &tunnelConn{Conn: conn, id: d.id, pr: d.pr}, nil
}

// tunnelConn is the tunnel handle: closing it closes the underlying conn and
// releases the tunnel (CloseTunnel) exactly once.
type tunnelConn struct {
	net.Conn
	id       string
	pr       TunnelProvider
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
	})
	return err
}