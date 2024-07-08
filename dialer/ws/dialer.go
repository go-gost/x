package ws

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/go-gost/core/dialer"
	md "github.com/go-gost/core/metadata"
	ws_util "github.com/go-gost/x/internal/util/ws"
	"github.com/go-gost/x/registry"
	"github.com/gorilla/websocket"
)

func init() {
	registry.DialerRegistry().Register("ws", NewDialer)
	registry.DialerRegistry().Register("wss", NewTLSDialer)
}

type wsDialer struct {
	tlsEnabled bool
	md         metadata
	options    dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &wsDialer{
		options: options,
	}
}

func NewTLSDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &wsDialer{
		tlsEnabled: true,
		options:    options,
	}
}

func (d *wsDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *wsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		d.options.Logger.Error(err)
	}
	return conn, err
}

// Handshake implements dialer.Handshaker
func (d *wsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	if d.md.handshakeTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	host := d.md.host
	if host == "" {
		host = opts.Addr
	}

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
		dialer.TLSClientConfig = d.options.TLSConfig
	}

	c, resp, err := dialer.DialContext(ctx, url.String(), d.md.header)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	cc := ws_util.Conn(c)

	if d.md.keepaliveInterval > 0 {
		d.options.Logger.Debugf("keepalive is enabled, ttl: %v", d.md.keepaliveInterval)
		c.SetReadDeadline(time.Now().Add(d.md.keepaliveInterval * 2))
		c.SetPongHandler(func(string) error {
			c.SetReadDeadline(time.Now().Add(d.md.keepaliveInterval * 2))
			d.options.Logger.Debugf("pong: set read deadline: %v", d.md.keepaliveInterval*2)
			return nil
		})
		go d.keepalive(cc)
	}

	return cc, nil
}

func (d *wsDialer) keepalive(conn ws_util.WebsocketConn) {
	ticker := time.NewTicker(d.md.keepaliveInterval)
	defer ticker.Stop()

	for range ticker.C {
		d.options.Logger.Debug("send ping")
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			// d.options.Logger.Error(err)
			return
		}
		conn.SetWriteDeadline(time.Time{})
	}
}
