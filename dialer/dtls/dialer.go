package dtls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/net/proxyproto"
	xdtls "github.com/go-gost/x/internal/util/dtls"
	"github.com/go-gost/x/registry"
	"github.com/pion/dtls/v3"
)

func init() {
	registry.DialerRegistry().Register("dtls", NewDialer)
}

type dtlsDialer struct {
	md      metadata
	logger  logger.Logger
	options dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &dtlsDialer{
		logger:  options.Logger,
		options: options,
	}
}

func (d *dtlsDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *dtlsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	conn, err := options.Dialer.Dial(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	conn = proxyproto.WrapClientConn(
		d.options.ProxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		conn)

	tlsCfg := d.options.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	c, err := dtls.ClientWithOptions(conn.(net.PacketConn), conn.RemoteAddr(),
		dtls.WithCertificates(tlsCfg.Certificates...),
		dtls.WithInsecureSkipVerify(tlsCfg.InsecureSkipVerify),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithServerName(tlsCfg.ServerName),
		dtls.WithRootCAs(tlsCfg.RootCAs),
		dtls.WithFlightInterval(d.md.flightInterval),
		dtls.WithMTU(d.md.mtu),
	)
	if err != nil {
		return nil, err
	}
	return xdtls.Conn(c, d.md.bufferSize), nil
}
