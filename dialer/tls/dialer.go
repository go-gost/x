package tls

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("tls", NewDialer)
}

type tlsDialer struct {
	md      metadata
	log     logger.Logger
	options dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tlsDialer{
		log:     options.Logger,
		options: options,
	}
}

func (d *tlsDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *tlsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		d.log.Error(err)
	}

	conn = proxyproto.WrapClientConn(
		d.options.ProxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		conn)

	return conn, err
}

// Handshake implements dialer.Handshaker
func (d *tlsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	tlsConn := tls.Client(conn, d.options.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}
