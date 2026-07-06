// plain http tunnel

package pht

import (
	"errors"
	"net"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	pht_util "github.com/go-gost/x/internal/util/pht"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("pht", NewListener)
	registry.ListenerRegistry().Register("phts", NewTLSListener)
}

type phtListener struct {
	addr       net.Addr
	tlsEnabled bool
	server     *pht_util.Server
	cqueue     chan net.Conn
	errChan    chan error
	logger     logger.Logger
	md         metadata
	options    listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &phtListener{
		logger:  options.Logger,
		options: options,
	}
}

func NewTLSListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &phtListener{
		tlsEnabled: true,
		logger:     options.Logger,
		options:    options,
	}
}

func (l *phtListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}
	l.addr, err = net.ResolveTCPAddr(network, l.options.Addr)
	if err != nil {
		return
	}

	l.server = pht_util.NewServer(
		l.options.Addr,
		pht_util.TLSConfigServerOption(l.options.TLSConfig),
		pht_util.EnableTLSServerOption(l.tlsEnabled),
		pht_util.BacklogServerOption(l.md.backlog),
		pht_util.PathServerOption(l.md.authorizePath, l.md.pushPath, l.md.pullPath),
		pht_util.LoggerServerOption(l.options.Logger),
		pht_util.MPTCPServerOption(l.md.mptcp),
	)

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go func() {
		if err := l.server.ListenAndServe(); err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()

	go func() {
		for {
			conn, err := l.server.Accept()
			if err != nil {
				return // server closed; ListenAndServe goroutine handles errChan
			}
			l.cqueue <- conn
		}
	}()

	// Verify the server started successfully. If ListenAndServe returned
	// immediately with an error (e.g., port already in use), surface it
	// now and clean up the bridging goroutine.
	select {
	case err = <-l.errChan:
		l.server.Close()
		return
	default:
	}

	return
}

func (l *phtListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.cqueue:
		if l.options.ConnLimiter != nil {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if lim := l.options.ConnLimiter.Limiter(host); lim != nil {
				if !lim.Allow(1) {
					conn.Close()
					return nil, errors.New("connection limit exceeded")
				}
				conn = climiter.WrapConn(lim, conn)
			}
		}
		conn = metrics.WrapConn(l.options.Service, conn)
		conn = stats.WrapConn(conn, l.options.Stats)
		conn = admission.WrapConn(l.options.Admission, conn)
		conn = limiter_wrapper.WrapConn(
			conn,
			l.options.TrafficLimiter,
			conn.RemoteAddr().String(),
			limiter.ScopeOption(limiter.ScopeConn),
			limiter.ServiceOption(l.options.Service),
			limiter.NetworkOption(conn.LocalAddr().Network()),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
	case err, ok = <-l.errChan:
		if !ok {
			err = listener.ErrClosed
		}
	}
	return
}

func (l *phtListener) Addr() net.Addr {
	return l.addr
}

func (l *phtListener) Close() (err error) {
	return l.server.Close()
}
