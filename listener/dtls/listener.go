package dtls

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	xdtls "github.com/go-gost/x/internal/util/dtls"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/pion/dtls/v2"
)

func init() {
	registry.ListenerRegistry().Register("dtls", NewListener)
}

type dtlsListener struct {
	ln      net.Listener
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &dtlsListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *dtlsListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "udp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "udp4"
	}
	laddr, err := net.ResolveUDPAddr(network, l.options.Addr)
	if err != nil {
		return
	}

	tlsCfg := l.options.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	config := dtls.Config{
		Certificates:         tlsCfg.Certificates,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 30*time.Second)
		},
		ClientCAs:      tlsCfg.ClientCAs,
		ClientAuth:     dtls.ClientAuthType(tlsCfg.ClientAuth),
		FlightInterval: l.md.flightInterval,
		MTU:            l.md.mtu,
	}

	ln, err := dtls.Listen(network, laddr, &config)
	if err != nil {
		return
	}
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Admission, ln)
	ln = limiter.WrapListener(l.options.TrafficLimiter, ln)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)

	l.ln = ln

	return
}

func (l *dtlsListener) Accept() (conn net.Conn, err error) {
	c, err := l.ln.Accept()
	if err != nil {
		return
	}
	conn = xdtls.Conn(c, l.md.bufferSize)
	return
}

func (l *dtlsListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *dtlsListener) Close() error {
	return l.ln.Close()
}
