package rudp

import (
	"context"
	"net"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	metrics "github.com/go-gost/core/metrics/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("rudp", NewListener)
}

type rudpListener struct {
	laddr   net.Addr
	ln      net.Listener
	router  *chain.Router
	closed  chan struct{}
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &rudpListener{
		closed:  make(chan struct{}),
		logger:  options.Logger,
		options: options,
	}
}

func (l *rudpListener) Init(md md.Metadata) (err error) {
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

	l.laddr = laddr
	l.router = (&chain.Router{}).
		WithChain(l.options.Chain).
		WithLogger(l.logger)

	return
}

func (l *rudpListener) Accept() (conn net.Conn, err error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	if l.ln == nil {
		l.ln, err = l.router.Bind(
			context.Background(), "udp", l.laddr.String(),
			connector.BacklogBindOption(l.md.backlog),
			connector.UDPConnTTLBindOption(l.md.ttl),
			connector.UDPDataBufferSizeBindOption(l.md.readBufferSize),
			connector.UDPDataQueueSizeBindOption(l.md.readQueueSize),
		)
		if err != nil {
			return nil, listener.NewAcceptError(err)
		}
	}
	conn, err = l.ln.Accept()
	if err != nil {
		l.ln.Close()
		l.ln = nil
		return nil, listener.NewAcceptError(err)
	}

	if pc, ok := conn.(net.PacketConn); ok {
		conn = metrics.WrapUDPConn(l.options.Service, pc)
	}

	return
}

func (l *rudpListener) Addr() net.Addr {
	return l.laddr
}

func (l *rudpListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
		if l.ln != nil {
			l.ln.Close()
			l.ln = nil
		}
	}

	return nil
}
