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

	return &mtcpDialer{
		sessions: make(map[string]*muxSession),
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
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
	if session != nil && session.IsClosed() {
		// A session still waiting for its handshake is not dead: its conn
		// belongs to the request that dialed it, whose Handshake either
		// builds the session on it or closes it. Only an established
		// session's base conn is closed here.
		if session.session != nil {
			session.Close()
			if session.conn != nil {
				session.conn.Close() // base conn would otherwise leak (and hold a p2p tunnel open)
			}
		}
		delete(d.sessions, addr)
		ok = false
	}
	if !ok {
		var options dialer.DialOptions
		for _, opt := range opts {
			opt(&options)
		}

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

		session = &muxSession{conn: conn}
		d.sessions[addr] = session
	}

	return session.conn, err
}

// Handshake implements dialer.Handshaker
func (d *mtcpDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	session, ok := d.sessions[opts.Addr]
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
			delete(d.sessions, opts.Addr)
			return nil, err
		}
		session = s
		d.sessions[opts.Addr] = session
	}
	cc, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(d.sessions, opts.Addr)
		return nil, err
	}

	return cc, nil
}

func (d *mtcpDialer) initSession(ctx context.Context, conn net.Conn) (*muxSession, error) {
	// stream multiplex
	session, err := mux.ClientSession(conn, d.md.muxCfg)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}
