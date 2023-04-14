package tls

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("tls", NewListener)
}

type tlsListener struct {
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
	return &tlsListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *tlsListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}
	ln, err := net.Listen(network, l.options.Addr)
	if err != nil {
		return
	}
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Admission, ln)
	ln = limiter.WrapListener(l.options.TrafficLimiter, ln)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)

	l.ln = tls.NewListener(ln, l.options.TLSConfig)

	return
}

func (l *tlsListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *tlsListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *tlsListener) Close() error {
	return l.ln.Close()
}
