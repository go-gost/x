package rudp

import (
	"context"
	"net"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
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
	l.router = chain.NewRouter(
		chain.ChainRouterOption(l.options.Chain),
		chain.LoggerRouterOption(l.logger),
	)

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
			chain.BacklogBindOption(l.md.backlog),
			chain.UDPConnTTLBindOption(l.md.ttl),
			chain.UDPDataBufferSizeBindOption(l.md.readBufferSize),
			chain.UDPDataQueueSizeBindOption(l.md.readQueueSize),
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
		uc := metrics.WrapUDPConn(l.options.Service, pc)
		uc = admission.WrapUDPConn(l.options.Admission, uc)
		conn = limiter.WrapUDPConn(l.options.TrafficLimiter, uc)
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
			// l.ln = nil
		}
	}

	return nil
}
