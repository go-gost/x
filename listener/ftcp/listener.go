package ftcp

import (
	"net"

	"github.com/go-gost/core/common/util/udp"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	metrics "github.com/go-gost/core/metrics/wrapper"
	"github.com/go-gost/core/registry"
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

	laddr, err := net.ResolveTCPAddr("tcp", l.options.Addr)
	if err != nil {
		return
	}

	var conn net.PacketConn
	conn, err = tcpraw.Listen("tcp", l.options.Addr)
	if err != nil {
		return
	}
	conn = metrics.WrapPacketConn(l.options.Service, conn)

	l.ln = udp.NewListener(
		conn,
		laddr,
		l.md.backlog,
		l.md.readQueueSize, l.md.readBufferSize,
		l.md.ttl,
		l.logger)
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
