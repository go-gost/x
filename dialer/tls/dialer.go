package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/ech"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("tls", NewDialer)
}

type tlsDialer struct {
	md      metadata
	log     logger.Logger
	options dialer.Options

	ech *ech.Client
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
	if err = d.parseMetadata(md); err != nil {
		return err
	}

	if !d.md.ech {
		return nil
	}

	if d.md.echDoH == "" {
		return errors.New("ech: doh endpoint is required")
	}

	if cfg := d.options.TLSConfig; cfg != nil {
		if cfg.MinVersion != 0 && cfg.MinVersion < tls.VersionTLS13 {
			return errors.New("ech: TLS 1.3 is required")
		}
		if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
			return errors.New("ech: TLS 1.3 is required")
		}
	}

	var tlsCfg *tls.Config
	if d.md.echDoHInsecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	} else {
		tlsCfg = &tls.Config{}
	}

	c, err := ech.NewClient(
		d.md.echDoH,
		ech.TTLOption(d.md.echTTL),
		ech.TimeoutOption(d.md.echTimeout),
		ech.TLSConfigOption(tlsCfg),
		ech.LoggerOption(d.log),
	)
	if err != nil {
		return err
	}
	d.ech = c
	return nil
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

	xnet.ApplyNoDelay(conn)

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
