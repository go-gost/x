package mtls

import (
	"context"
	"crypto/tls"
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
	registry.DialerRegistry().Register("mtls", NewDialer)
}

type mtlsDialer struct {
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &mtlsDialer{
		sessions: make(map[string]*muxSession),
		logger:   options.Logger,
		options:  options,
	}
}

func (d *mtlsDialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	return d.md.ech.Init(d.logger, d.options.TLSConfig)
}

// Multiplex implements dialer.Multiplexer interface.
func (d *mtlsDialer) Multiplex() bool {
	return true
}

func (d *mtlsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
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
// has closed. A session still waiting for its handshake is not dead: its conn
// belongs to the request that dialed it, whose Handshake either builds the
// session on it or closes it. Only an established session's base conn is
// closed here.
func (d *mtlsDialer) sessionConn(addr string) net.Conn {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
	if !ok {
		return nil
	}
	if session.IsClosed() {
		if session.session != nil {
			session.Close()
			if session.conn != nil {
				session.conn.Close() // base conn would otherwise leak (and hold a p2p tunnel open)
			}
		}
		delete(d.sessions, addr)
		return nil
	}
	return session.conn
}

// Handshake implements dialer.Handshaker
func (d *mtlsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	session, err := d.sessionForHandshake(ctx, opts.Addr, conn)
	if err != nil {
		return nil, err
	}

	// The open runs outside the lock and is bounded by ctx: a stalled session
	// must not serialize the dials of every other service.
	cc, err := session.GetConnContext(ctx)
	if err != nil {
		session.Close()
		d.dropSession(opts.Addr, session)
		return nil, err
	}

	return cc, nil
}

// sessionForHandshake returns the session to open a stream on, building one on
// conn when none is live. It runs under sessionMutex so concurrent handshakes
// converge on a single session.
func (d *mtlsDialer) sessionForHandshake(ctx context.Context, addr string, conn net.Conn) (*muxSession, error) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
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
		s, err := d.initSession(ctx, conn)
		if err != nil {
			d.logger.Error(err)
			conn.Close()
			delete(d.sessions, addr)
			return nil, err
		}
		session = s
		d.sessions[addr] = session
	}

	return session, nil
}

// dropSession closes and forgets session, but only while it is still the one
// cached for addr: a concurrent handshake may have replaced it.
func (d *mtlsDialer) dropSession(addr string, session *muxSession) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if cur, ok := d.sessions[addr]; ok && cur == session {
		cur.Close()
		if cur.conn != nil {
			cur.conn.Close()
		}
		delete(d.sessions, addr)
	}
}

func (d *mtlsDialer) initSession(ctx context.Context, conn net.Conn) (*muxSession, error) {
	serverName := ""
	if d.options.TLSConfig != nil {
		serverName = d.options.TLSConfig.ServerName
	}
	cfg, err := d.md.ech.Apply(ctx, d.options.TLSConfig, serverName)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if rerr := d.md.ech.OnRejection(err, serverName); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	conn = tlsConn

	// stream multiplex
	session, err := mux.ClientSession(conn, d.md.muxCfg)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}
