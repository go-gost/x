package http2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/net/proxyproto"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	mdx "github.com/go-gost/x/metadata"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
	"golang.org/x/net/http2"
)

func init() {
	registry.ListenerRegistry().Register("http2", NewListener)
}

type http2Listener struct {
	server  *http.Server
	addr    net.Addr
	cqueue  chan net.Conn
	errChan chan error
	log     logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &http2Listener{
		log:     options.Logger,
		options: options,
	}
}

func (l *http2Listener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	l.server = &http.Server{
		Addr:      l.options.Addr,
		Handler:   http.HandlerFunc(l.handleFunc),
		TLSConfig: l.options.TLSConfig,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tlsConn, ok := c.(*tls.Conn); ok {
				if cc, ok := tlsConn.NetConn().(xctx.Context); ok {
					if cv := cc.Context(); cv != nil {
						return cv
					}
				}
			}
			if cc, ok := c.(xctx.Context); ok {
				if cv := cc.Context(); cv != nil {
					return cv
				}
			}
			return ctx
		},
	}
	if err := http2.ConfigureServer(l.server, nil); err != nil {
		return err
	}

	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}
	lc := net.ListenConfig{}
	if l.md.mptcp {
		lc.SetMultipathTCP(true)
		l.log.Debugf("mptcp enabled: %v", lc.MultipathTCP())
	}
	ln, err := lc.Listen(context.Background(), network, l.options.Addr)
	if err != nil {
		return err
	}
	l.addr = ln.Addr()
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = stats.WrapListener(ln, l.options.Stats)
	ln = admission.WrapListener(l.options.Service, l.options.Admission, ln)
	ln = limiter_wrapper.WrapListener(l.options.Service, ln, l.options.TrafficLimiter)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)
	ln = tls.NewListener(
		ln,
		l.options.TLSConfig,
	)

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go func() {
		if err := l.server.Serve(ln); err != nil {
			l.log.Error(err)
		}
	}()

	return
}

func (l *http2Listener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.cqueue:
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

func (l *http2Listener) Addr() net.Addr {
	return l.addr
}

func (l *http2Listener) Close() (err error) {
	select {
	case <-l.errChan:
	default:
		err = l.server.Close()
		l.errChan <- http.ErrServerClosed
		close(l.errChan)
	}
	return
}

func (l *http2Listener) handleFunc(w http.ResponseWriter, r *http.Request) {
	remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{
			IP: net.IPv4zero,
		}
	}

	ctx := r.Context()
	if clientIP := xhttp.GetClientIP(r); clientIP != nil {
		ctx = xctx.ContextWithSrcAddr(ctx, &net.TCPAddr{IP: clientIP})
	}

	ctx = ictx.ContextWithMetadata(ctx, mdx.NewMetadata(map[string]any{
		"r": r,
		"w": w,
	}))

	ctx, cancel := context.WithCancel(ctx)
	conn := &conn{
		laddr:  l.addr,
		raddr:  remoteAddr,
		ctx:    ctx,
		cancel: cancel,
		closed: make(chan struct{}),
	}

	select {
	case l.cqueue <- conn:
	default:
		l.log.Warnf("connection queue is full, client %s discarded", r.RemoteAddr)
		return
	}

	// NOTE: we need to wait for conn closed, or the connection will be closed.
	<-conn.closed
}
