package rtcp

import (
	"context"
	"net"
	"sync"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("rtcp", NewListener)
}

type rtcpListener struct {
	laddr   net.Addr
	ln      net.Listener
	logger  logger.Logger
	closed  chan struct{}
	md      metadata
	options listener.Options
	mu      sync.Mutex
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &rtcpListener{
		closed:  make(chan struct{}),
		logger:  options.Logger,
		options: options,
	}
}

func (l *rtcpListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}
	if laddr, _ := net.ResolveTCPAddr(network, l.options.Addr); laddr != nil {
		l.laddr = laddr
	}
	if l.laddr == nil {
		l.laddr = &bindAddr{addr: l.options.Addr}
	}

	return
}

func (l *rtcpListener) Accept() (conn net.Conn, err error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	ln := l.getListener()
	if ln == nil {
		ln, err = l.options.Router.Bind(
			context.Background(), "tcp", l.laddr.String(),
			chain.MuxBindOption(true),
		)
		if err != nil {
			return nil, listener.NewAcceptError(err)
		}
		ln = metrics.WrapListener(l.options.Service, ln)
		ln = stats.WrapListener(ln, l.options.Stats)
		ln = admission.WrapListener(l.options.Admission, ln)
		ln = limiter_wrapper.WrapListener(l.options.Service, ln, l.options.TrafficLimiter)
		ln = climiter.WrapListener(l.options.ConnLimiter, ln)
		l.setListener(ln)
	}

	select {
	case <-l.closed:
		ln.Close()
		return nil, net.ErrClosed
	default:
	}

	conn, err = ln.Accept()
	if err != nil {
		ln.Close()
		l.setListener(nil)
		return nil, listener.NewAcceptError(err)
	}

	conn = limiter_wrapper.WrapConn(
		conn,
		l.options.TrafficLimiter,
		conn.RemoteAddr().String(),
		limiter.ScopeOption(limiter.ScopeConn),
		limiter.ServiceOption(l.options.Service),
		limiter.NetworkOption(conn.LocalAddr().Network()),
		limiter.SrcOption(conn.RemoteAddr().String()),
	)

	return
}

func (l *rtcpListener) Addr() net.Addr {
	return l.laddr
}

func (l *rtcpListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
		if ln := l.getListener(); ln != nil {
			ln.Close()
		}
	}

	return nil
}

func (l *rtcpListener) setListener(ln net.Listener) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ln = ln
}

func (l *rtcpListener) getListener() net.Listener {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ln
}

type bindAddr struct {
	addr string
}

func (p *bindAddr) Network() string {
	return "tcp"
}

func (p *bindAddr) String() string {
	return p.addr
}
