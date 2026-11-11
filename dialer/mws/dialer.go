package mws

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/mux"
	ws_util "github.com/go-gost/x/internal/util/ws"
	"github.com/go-gost/x/registry"
	"github.com/gorilla/websocket"
)

func init() {
	registry.DialerRegistry().Register("mws", NewDialer)
	registry.DialerRegistry().Register("mwss", NewTLSDialer)
}

type mwsDialer struct {
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex // guards sessions and builders
	builders     map[string]*sessionBuilder
	tlsEnabled   bool
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

	return &mwsDialer{
		sessions: make(map[string]*muxSession),
		builders: make(map[string]*sessionBuilder),
		options:  options,
	}
}

func NewTLSDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &mwsDialer{
		tlsEnabled: true,
		sessions:   make(map[string]*muxSession),
		builders:   make(map[string]*sessionBuilder),
		options:    options,
	}
}
func (d *mwsDialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	if !d.tlsEnabled {
		return nil
	}
	return d.md.ech.Init(d.options.Logger, d.options.TLSConfig)
}

// Multiplex implements dialer.Multiplexer interface.
func (d *mwsDialer) Multiplex() bool {
	return true
}

func (d *mwsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
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

	if d.md.tcpKeepalive {
		xnet.ApplyKeepalive(conn, net.KeepAliveConfig{
			Enable:   true,
			Idle:     d.md.tcpKeepaliveIdle,
			Interval: d.md.tcpKeepaliveInterval,
			Count:    d.md.tcpKeepaliveCount,
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
func (d *mwsDialer) sessionConn(addr string) net.Conn {
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
			d.options.Logger.Debugf("mux session %s closed, reconnecting", addr)
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
func (d *mwsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	log := d.options.Logger.WithFields(map[string]any{
		"local":  conn.LocalAddr().String(),
		"remote": conn.RemoteAddr().String(),
	})

	session, err := d.sessionForHandshake(ctx, opts.Addr, conn, log)
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
func (d *mwsDialer) sessionForHandshake(ctx context.Context, addr string, conn net.Conn, log logger.Logger) (*muxSession, error) {
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
		// initSession bounds its own websocket handshake, so no deadline is
		// set on conn here.
		host := d.md.host
		if host == "" {
			host = addr
		}
		s, err := d.initSession(ctx, host, conn, log, addr)
		if err != nil {
			log.Error(err)
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
func (d *mwsDialer) builderFor(addr string) *sessionBuilder {
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
func (d *mwsDialer) releaseBuilder(addr string, b *sessionBuilder) {
	b.mu.Unlock()

	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if b.refs--; b.refs == 0 {
		delete(d.builders, addr)
	}
}

// forgetSession drops the cache entry for addr while it is still session.
func (d *mwsDialer) forgetSession(addr string, session *muxSession) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if cur, ok := d.sessions[addr]; ok && cur == session {
		delete(d.sessions, addr)
	}
}

// dropSession retires session after a failed open: the cache entry goes if it
// is still that session, and the session itself is closed outside the mutex
// because a backend's Close may wait for its own send loop.
func (d *mwsDialer) dropSession(addr string, session *muxSession) {
	d.sessionMutex.Lock()
	if cur, ok := d.sessions[addr]; ok && cur == session {
		delete(d.sessions, addr)
	}
	d.sessionMutex.Unlock()

	d.options.Logger.Warnf("mux session %s unusable, reconnecting", addr)
	session.Close()
	if session.conn != nil {
		session.conn.Close()
	}
}

func (d *mwsDialer) initSession(ctx context.Context, host string, conn net.Conn, log logger.Logger, optAddr string) (*muxSession, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout:  d.md.handshakeTimeout,
		ReadBufferSize:    d.md.readBufferSize,
		WriteBufferSize:   d.md.writeBufferSize,
		EnableCompression: d.md.enableCompression,
		NetDial: func(net, addr string) (net.Conn, error) {
			return conn, nil
		},
	}

	url := url.URL{Scheme: "ws", Host: host, Path: d.md.path}
	if d.tlsEnabled {
		url.Scheme = "wss"
		serverName := ""
		if d.options.TLSConfig != nil {
			serverName = d.options.TLSConfig.ServerName
		}
		cfg, err := d.md.ech.Apply(ctx, d.options.TLSConfig, serverName)
		if err != nil {
			return nil, err
		}
		dialer.TLSClientConfig = cfg
	}

	if d.md.handshakeTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(d.md.handshakeTimeout))
	}

	c, resp, err := dialer.DialContext(ctx, url.String(), d.md.header)
	if err != nil {
		if d.tlsEnabled {
			serverName := ""
			if d.options.TLSConfig != nil {
				serverName = d.options.TLSConfig.ServerName
			}
			if rerr := d.md.ech.OnRejection(err, serverName); rerr != nil {
				return nil, rerr
			}
		}
		return nil, err
	}
	resp.Body.Close()

	if d.md.handshakeTimeout > 0 {
		conn.SetReadDeadline(time.Time{})
	}

	cc := ws_util.Conn(c)

	if d.md.keepaliveInterval > 0 {
		log.Debugf("keepalive is enabled, ttl: %v", d.md.keepaliveInterval)
		c.SetReadDeadline(time.Now().Add(d.md.keepaliveInterval * 2))
		c.SetPongHandler(func(string) error {
			c.SetReadDeadline(time.Now().Add(d.md.keepaliveInterval * 2))
			return nil
		})
		go d.keepAlive(cc, optAddr)
	}

	// stream multiplex
	session, err := mux.ClientSession(cc, d.md.muxCfg)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &muxSession{conn: cc, session: session}, nil
}

func (d *mwsDialer) keepAlive(conn ws_util.WebsocketConn, optAddr string) {
	ticker := time.NewTicker(d.md.keepaliveInterval)
	defer ticker.Stop()

	for range ticker.C {
		d.options.Logger.Debug("send ping")
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {

			// Drop the cached session only while it is still this conn's: a
			// newer session may have replaced it meanwhile.
			d.sessionMutex.Lock()
			if session, ok := d.sessions[optAddr]; ok && session.conn == net.Conn(conn) {
				delete(d.sessions, optAddr)
			}
			d.sessionMutex.Unlock()
			conn.Close()
			return
		}
		conn.SetWriteDeadline(time.Time{})
	}
}
