package udp

import (
	"net"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("redu", NewListener)
}

type redirectListener struct {
	ln      *net.UDPConn
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &redirectListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *redirectListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	ln, err := l.listenUDP(l.options.Addr)
	if err != nil {
		return
	}

	l.ln = ln
	return
}

func (l *redirectListener) Accept() (conn net.Conn, err error) {
	conn, err = l.accept()
	if err != nil {
		return
	}
	conn = metrics.WrapConn(l.options.Service, conn)
	conn = admission.WrapConn(l.options.Admission, conn)
	conn = limiter.WrapConn(l.options.TrafficLimiter, conn)
	return
}

func (l *redirectListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *redirectListener) Close() error {
	return l.ln.Close()
}
