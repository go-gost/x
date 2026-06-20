package utls

import (
	"context"
	"crypto/tls"
	"net"
	"time"
	"unsafe"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/registry"
	utls "github.com/refraction-networking/utls"
)

func init() {
	registry.DialerRegistry().Register("utls", NewDialer)
}

type utlsDialer struct {
	md      metadata
	log     logger.Logger
	options dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &utlsDialer{
		log:     options.Logger,
		options: options,
	}
}

func (d *utlsDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *utlsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		d.log.Error(err)
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

	return conn, err
}

// Handshake implements dialer.Handshaker.
func (d *utlsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	clientHelloID, ok := GetClientHelloID(d.md.fingerprint)
	if ok {
		d.log.Debugf("utls handshake with fingerprint: %s", d.md.fingerprint)
		utlsCfg := (*utls.Config)(unsafe.Pointer(d.options.TLSConfig))
		uconn := utls.UClient(conn, utlsCfg, clientHelloID)
		if err := uconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return uconn, nil
	}

	// fingerprint not set, empty, "golang", or unknown: fall through to
	// standard crypto/tls.
	if d.md.fingerprint != "" {
		d.log.Warnf("unknown utls fingerprint: %s, falling back to standard TLS", d.md.fingerprint)
	}
	tlsConn := tls.Client(conn, d.options.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}
