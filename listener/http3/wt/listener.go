package wt

import (
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	wt_util "github.com/go-gost/x/internal/util/wt"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
	stats "github.com/go-gost/x/stats/wrapper"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	wt "github.com/quic-go/webtransport-go"
)

func init() {
	registry.ListenerRegistry().Register("wt", NewListener)
}

type wtListener struct {
	addr    net.Addr
	srv     *wt.Server
	cqueue  chan net.Conn
	errChan chan error
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &wtListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *wtListener) Init(md md.Metadata) (err error) {
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

	mux := http.NewServeMux()
	mux.Handle(l.md.path, http.HandlerFunc(l.upgrade))

	l.srv = &wt.Server{
		H3: http3.Server{
			Addr:      l.options.Addr,
			TLSConfig: l.options.TLSConfig,
			QuicConfig: &quic.Config{
				KeepAlivePeriod:      l.md.keepAlivePeriod,
				HandshakeIdleTimeout: l.md.handshakeTimeout,
				MaxIdleTimeout:       l.md.maxIdleTimeout,
				/*
					Versions: []quic.VersionNumber{
						quic.Version1,
						quic.Version2,
					},
				*/
				MaxIncomingStreams: int64(l.md.maxStreams),
			},
			Handler: mux,
		},
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go func() {
		if err := l.srv.ListenAndServe(); err != nil {
			l.logger.Error(err)
		}
	}()

	return
}

func (l *wtListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.cqueue:
		conn = metrics.WrapConn(l.options.Service, conn)
		conn = stats.WrapConn(conn, l.options.Stats)
		conn = admission.WrapConn(l.options.Admission, conn)
		conn = limiter.WrapConn(l.options.TrafficLimiter, conn)
	case err, ok = <-l.errChan:
		if !ok {
			err = listener.ErrClosed
		}
	}
	return
}

func (l *wtListener) Addr() net.Addr {
	return l.addr
}

func (l *wtListener) Close() (err error) {
	return l.srv.Close()
}

func (l *wtListener) upgrade(w http.ResponseWriter, r *http.Request) {
	log := l.logger.WithFields(map[string]any{
		"local":  l.addr.String(),
		"remote": r.RemoteAddr,
	})
	if l.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Trace(string(dump))
	}

	s, err := l.srv.Upgrade(w, r)
	if err != nil {
		l.logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	l.mux(s, log)
}

func (l *wtListener) mux(s *wt.Session, log logger.Logger) (err error) {
	defer func() {
		if err != nil {
			s.CloseWithError(1, err.Error())
		} else {
			s.CloseWithError(0, "")
		}
	}()

	for {
		var stream wt.Stream
		stream, err = s.AcceptStream(s.Context())
		if err != nil {
			log.Errorf("accept stream: %v", err)
			return
		}

		select {
		case l.cqueue <- wt_util.Conn(s, stream):
		default:
			stream.Close()
			l.logger.Warnf("connection queue is full, stream %v discarded", stream.StreamID())
		}
	}
}
