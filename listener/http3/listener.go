package http3

import (
	"net"
	"net/http"
	"sync"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	registry.ListenerRegistry().Register("http3", NewListener)
}

type http3Listener struct {
	server  *http3.Server
	addr    net.Addr
	cqueue  chan net.Conn
	errChan chan error
	logger  logger.Logger
	md      metadata
	options listener.Options
	mu      sync.Mutex
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

	addr := l.options.Addr
	if addr == "" {
		addr = ":https"
	}

	network := "udp"
	if xnet.IsIPv4(addr) {
		network = "udp4"
	}
	l.addr, err = net.ResolveUDPAddr(network, addr)
	if err != nil {
		return
	}

	l.server = &http3.Server{
		Addr:      l.options.Addr,
		TLSConfig: l.options.TLSConfig,
		QUICConfig: &quic.Config{
			KeepAlivePeriod:      l.md.keepAlivePeriod,
			HandshakeIdleTimeout: l.md.handshakeTimeout,
			MaxIdleTimeout:       l.md.maxIdleTimeout,
			Versions: []quic.Version{
				quic.Version1,
			},
			MaxIncomingStreams: int64(l.md.maxStreams),
			Allow0RTT:          true,
		},
		Handler: http.HandlerFunc(l.handleFunc),
	}

	ln, err := quic.ListenAddrEarly(addr, http3.ConfigureTLSConfig(l.server.TLSConfig), l.server.QUICConfig.Clone())
	if err != nil {
		return
	}

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go func() {
		if err := l.server.ServeListener(ln); err != nil {
			l.logger.Error(err)
		}
	}()

	return
}

func (l *http3Listener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.cqueue:
	case err, ok = <-l.errChan:
		if !ok {
			err = listener.ErrClosed
		}
	}
	return
}

func (l *http3Listener) Addr() net.Addr {
	return l.addr
}

func (l *http3Listener) Close() (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	select {
	case <-l.errChan:
	default:
		err = l.server.Close()
		l.errChan <- err
		close(l.errChan)
	}
	return nil
}

func (l *http3Listener) handleFunc(w http.ResponseWriter, r *http.Request) {
	raddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	conn := &conn{
		laddr:  l.addr,
		raddr:  raddr,
		closed: make(chan struct{}),
		md: mdx.NewMetadata(map[string]any{
			"r": r,
			"w": w,
		}),
	}
	select {
	case l.cqueue <- conn:
	default:
		l.logger.Warnf("connection queue is full, client %s discarded", r.RemoteAddr)
		return
	}

	<-conn.Done()
}
