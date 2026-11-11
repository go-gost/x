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
	sessionMutex sync.Mutex
	tlsEnabled   bool
	md           metadata
	options      dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &mwsDialer{
		sessions: make(map[string]*muxSession),
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
// has closed. A session still waiting for its handshake is not dead: its conn
// belongs to the request that dialed it, whose Handshake either builds the
// session on it or closes it. Only an established session's base conn is
// closed here.
func (d *mwsDialer) sessionConn(addr string) net.Conn {
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
func (d *mwsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	log := d.options.Logger.WithFields(map[string]any{
		"local":  conn.LocalAddr().String(),
		"remote": conn.RemoteAddr().String(),
	})

	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	session, err := d.sessionForHandshake(ctx, opts.Addr, conn, log)
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
func (d *mwsDialer) sessionForHandshake(ctx context.Context, addr string, conn net.Conn, log logger.Logger) (*muxSession, error) {
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
		host := d.md.host
		if host == "" {
			host = addr
		}
		s, err := d.initSession(ctx, host, conn, log, addr)
		if err != nil {
			log.Error(err)
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
func (d *mwsDialer) dropSession(addr string, session *muxSession) {
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
