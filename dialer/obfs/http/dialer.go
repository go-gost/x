package http

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("ohttp", NewDialer)
	registry.DialerRegistry().Register("ohttps", NewDialer)
}

type obfsHTTPDialer struct {
	tlsEnabled bool
	md         metadata
	logger     logger.Logger
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}

	return &obfsHTTPDialer{
		logger: options.Logger,
	}
}

func NewTLSDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}

	return &obfsHTTPDialer{
		tlsEnabled: true,
		logger:     options.Logger,
	}
}

func (d *obfsHTTPDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *obfsHTTPDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	options := &dialer.DialOptions{}
	for _, opt := range opts {
		opt(options)
	}

	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		d.logger.Error(err)
	}
	return conn, err
}

// Handshake implements dialer.Handshaker
func (d *obfsHTTPDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	host := d.md.host
	if host == "" {
		host = opts.Addr
	}

	if d.tlsEnabled {
		conn = tls.Client(conn, &tls.Config{
			ServerName: host,
		})
	}

	return &obfsHTTPConn{
		Conn:   conn,
		host:   host,
		path:   d.md.path,
		header: d.md.header,
		logger: d.logger,
	}, nil
}
