package h3

import (
	"net"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	pht_util "github.com/go-gost/x/internal/util/pht"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/quic-go/quic-go"
)

func init() {
	registry.ListenerRegistry().Register("h3", NewListener)
}

type http3Listener struct {
	addr    net.Addr
	server  *pht_util.Server
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &http3Listener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *http3Listener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "udp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "udp4"
	}
	l.addr, err = net.ResolveUDPAddr(network, l.options.Addr)
	if err != nil {
		return
	}

	l.server = pht_util.NewHTTP3Server(
		l.options.Addr,
		&quic.Config{
			KeepAlivePeriod:      l.md.keepAlivePeriod,
			HandshakeIdleTimeout: l.md.handshakeTimeout,
			MaxIdleTimeout:       l.md.maxIdleTimeout,
			Versions: []quic.Version{
				quic.Version1,
			},
			MaxIncomingStreams: int64(l.md.maxStreams),
		},
		pht_util.TLSConfigServerOption(l.options.TLSConfig),
		pht_util.BacklogServerOption(l.md.backlog),
		pht_util.PathServerOption(l.md.authorizePath, l.md.pushPath, l.md.pullPath),
		pht_util.LoggerServerOption(l.options.Logger),
	)

	go func() {
		if err := l.server.ListenAndServe(); err != nil {
			l.logger.Error(err)
		}
	}()

	return
}

func (l *http3Listener) Accept() (conn net.Conn, err error) {
	conn, err = l.server.Accept()
	if err != nil {
		return
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
	return conn, nil
}

func (l *http3Listener) Addr() net.Addr {
	return l.addr
}

func (l *http3Listener) Close() (err error) {
	return l.server.Close()
}
