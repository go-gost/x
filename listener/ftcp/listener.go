package ftcp

import (
	"net"

	"github.com/go-gost/core/common/net/udp"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/xtaci/tcpraw"
)

func init() {
	registry.ListenerRegistry().Register("ftcp", NewListener)
}

type ftcpListener struct {
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
	return &ftcpListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *ftcpListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	var conn net.PacketConn
	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}
	conn, err = tcpraw.Listen(network, l.options.Addr)
	if err != nil {
		return
	}
	conn = metrics.WrapPacketConn(l.options.Service, conn)
	conn = admission.WrapPacketConn(l.options.Admission, conn)
	conn = limiter.WrapPacketConn(l.options.TrafficLimiter, conn)

	l.ln = udp.NewListener(
		conn,
		&udp.ListenConfig{
			Backlog:        l.md.backlog,
			ReadQueueSize:  l.md.readQueueSize,
			ReadBufferSize: l.md.readBufferSize,
			TTL:            l.md.ttl,
			KeepAlive:      true,
			Logger:         l.logger,
		})
	return
}

func (l *ftcpListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *ftcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *ftcpListener) Close() error {
	return l.ln.Close()
}
