package mtcp

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("mtcp", NewDialer)
}

type mtcpDialer struct {
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex // guards sessions and builders
	builders     map[string]*sessionBuilder
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

// sessionBuilder serializes session creation for one address, so concurrent
// handshakes converge on one session without holding up dials to any other
// address or the reuse fast path.
type sessionBuilder struct {
	mu   sync.Mutex
	refs int
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &mtcpDialer{
		sessions: make(map[string]*muxSession),
		builders: make(map[string]*sessionBuilder),
		logger:   options.Logger,
		options:  options,
	}
}

func (d *mtcpDialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	return nil
}

// Multiplex implements dialer.Multiplexer interface.
func (d *mtcpDialer) Multiplex() bool {
	return true
}

func (d *mtcpDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
	// Fast path: hand back the live session's conn. Only the map is touched
	// here, so a dial that is still connecting can not hold this one up.
	if conn := d.sessionConn(addr); conn != nil {
		return conn, nil
	}

	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	// The dial runs outside sessionMutex: an unreachable node must not stall
	// dials to other addresses.
	conn, err = options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		return
	}

	if d.md.keepalive {
		xnet.ApplyKeepalive(conn, net.KeepAliveConfig{
			Enable:   true,
			Idle:     d.md.keepaliveIdle,
			Interval: d.md.keepaliveInterval,
			Count:    d.md.keepaliveCount,
		})
	}

	conn = proxyproto.WrapClientConn(
		d.options.ProxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		conn)

	// Register the conn as a session still waiting for its handshake. A racing
	// Dial may have registered one meanwhile; that one wins and this conn is
	// dropped.
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()
	if session, ok := d.sessions[addr]; ok && !session.IsClosed() {
		conn.Close()
		return session.conn, nil
	}
	d.sessions[addr] = &muxSession{conn: conn}
	return conn, nil
}

// sessionConn returns the conn of a usable session for addr, dropping one that
// has closed. A placeholder (a conn whose handshake has not run yet) reports
// closed by design: its conn belongs to the request that dialed it, whose
// Handshake either builds the session on it or closes it, so only an
// established session's base conn is closed here. Closing happens outside the
// mutex because a backend's Close may wait for its own send loop.
func (d *mtcpDialer) sessionConn(addr string) net.Conn {
	d.sessionMutex.Lock()
	session, ok := d.sessions[addr]
	if ok && session.IsClosed() {
		delete(d.sessions, addr)
	}
	d.sessionMutex.Unlock()

	if !ok {
		return nil
	}
	if session.IsClosed() {
		if session.session != nil {
			d.logger.Debugf("mux session %s closed, reconnecting", addr)
			session.Close()
			if session.conn != nil {
				session.conn.Close() // base conn would otherwise leak (and hold a p2p tunnel open)
			}
		}
		return nil
	}
	return session.conn
}

// Handshake implements dialer.Handshaker
func (d *mtcpDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	session, err := d.sessionForHandshake(ctx, opts.Addr, conn)
	if err != nil {
		return nil, err
	}

	// The open runs outside the lock and is bounded by ctx: a stalled session
	// must not serialize the dials of every other service.
	cc, err := session.GetConnContext(ctx)
	if err != nil {
		d.dropSession(opts.Addr, session)
		return nil, err
	}

	return cc, nil
}

// sessionForHandshake returns the session to open a stream on, building one on
// conn when none is live. Building runs under a per-address builder, so
// concurrent handshakes for that address converge on one session while dials to
// other addresses keep going. The handshake deadline is applied here, on a conn
// this caller owns: the reuse path shares the session's base conn, and a
// deadline there would interrupt every stream multiplexed on it.
func (d *mtcpDialer) sessionForHandshake(ctx context.Context, addr string, conn net.Conn) (*muxSession, error) {
	b := d.builderFor(addr)
	defer d.releaseBuilder(addr, b)
	b.mu.Lock()

	d.sessionMutex.Lock()
	session, ok := d.sessions[addr]
	d.sessionMutex.Unlock()

	if session != nil && session.conn != conn {
		// Another Dial registered a conn of its own while this one waited
		// for the lock. If it has become a live session, use that and drop
		// this conn; otherwise build the session on this conn, and the other
		// request's Handshake will find it here and use it.
		if session.IsClosed() {
			ok = false
		} else {
			conn.Close()
		}
	}

	if !ok || session.session == nil {
		if d.md.handshakeTimeout > 0 {
			conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
			defer conn.SetDeadline(time.Time{})
		}
		s, err := d.initSession(ctx, conn)
		if err != nil {
			d.logger.Error(err)
			conn.Close()
			d.forgetSession(addr, session)
			return nil, err
		}
		session = s
		d.sessionMutex.Lock()
		d.sessions[addr] = session
		d.sessionMutex.Unlock()
	}

	return session, nil
}

// builderFor returns the builder for addr with a reference held.
func (d *mtcpDialer) builderFor(addr string) *sessionBuilder {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	b, ok := d.builders[addr]
	if !ok {
		b = &sessionBuilder{}
		d.builders[addr] = b
	}
	b.refs++

	return b
}

// releaseBuilder unlocks b and drops it once no caller holds it.
func (d *mtcpDialer) releaseBuilder(addr string, b *sessionBuilder) {
	b.mu.Unlock()

	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if b.refs--; b.refs == 0 {
		delete(d.builders, addr)
	}
}

// forgetSession drops the cache entry for addr while it is still session.
func (d *mtcpDialer) forgetSession(addr string, session *muxSession) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if cur, ok := d.sessions[addr]; ok && cur == session {
		delete(d.sessions, addr)
	}
}

// dropSession retires session after a failed open: the cache entry goes if it
// is still that session, and the session itself is closed outside the mutex
// because a backend's Close may wait for its own send loop.
func (d *mtcpDialer) dropSession(addr string, session *muxSession) {
	d.sessionMutex.Lock()
	if cur, ok := d.sessions[addr]; ok && cur == session {
		delete(d.sessions, addr)
	}
	d.sessionMutex.Unlock()

	d.logger.Warnf("mux session %s unusable, reconnecting", addr)
	session.Close()
	if session.conn != nil {
		session.conn.Close()
	}
}

func (d *mtcpDialer) initSession(ctx context.Context, conn net.Conn) (*muxSession, error) {
	// stream multiplex
	session, err := mux.ClientSession(conn, d.md.muxCfg)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}
