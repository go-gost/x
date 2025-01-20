package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	traffic_limiter "github.com/go-gost/x/limiter/traffic"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/miekg/dns"
)

func init() {
	registry.ListenerRegistry().Register("dns", NewListener)
}

type dnsListener struct {
	addr    net.Addr
	server  Server
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
	return &dnsListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *dnsListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	switch strings.ToLower(l.md.mode) {
	case "tcp":
		l.addr, err = net.ResolveTCPAddr("tcp", l.options.Addr)
		if err != nil {
			return
		}

		network := "tcp"
		if xnet.IsIPv4(l.options.Addr) {
			network = "tcp4"
		}

		lc := net.ListenConfig{}
		if l.md.mptcp {
			lc.SetMultipathTCP(true)
			l.logger.Debugf("mptcp enabled: %v", lc.MultipathTCP())
		}

		var ln net.Listener
		ln, err = lc.Listen(context.Background(), network, l.options.Addr)
		if err != nil {
			return
		}

		ln = limiter_wrapper.WrapListener(l.options.Service, ln, l.options.TrafficLimiter)

		l.server = &dnsServer{
			server: &dns.Server{
				Net:          "tcp",
				Addr:         l.options.Addr,
				Listener:     ln,
				Handler:      l,
				ReadTimeout:  l.md.readTimeout,
				WriteTimeout: l.md.writeTimeout,
			},
		}

	case "tls":
		l.addr, err = net.ResolveTCPAddr("tcp", l.options.Addr)
		if err != nil {
			return
		}

		network := "tcp"
		if xnet.IsIPv4(l.options.Addr) {
			network = "tcp4"
		}

		lc := net.ListenConfig{}
		if l.md.mptcp {
			lc.SetMultipathTCP(true)
			l.logger.Debugf("mptcp enabled: %v", lc.MultipathTCP())
		}

		var ln net.Listener
		ln, err = lc.Listen(context.Background(), network, l.options.Addr)
		if err != nil {
			return
		}
		ln = tls.NewListener(ln, l.options.TLSConfig)

		ln = limiter_wrapper.WrapListener(l.options.Service, ln, l.options.TrafficLimiter)

		l.server = &dnsServer{
			server: &dns.Server{
				Net:          "tcp-tls",
				Addr:         l.options.Addr,
				Listener:     ln,
				Handler:      l,
				TLSConfig:    l.options.TLSConfig,
				ReadTimeout:  l.md.readTimeout,
				WriteTimeout: l.md.writeTimeout,
			},
		}

	case "https":
		l.addr, err = net.ResolveTCPAddr("tcp", l.options.Addr)
		if err != nil {
			return
		}

		network := "tcp"
		if xnet.IsIPv4(l.options.Addr) {
			network = "tcp4"
		}

		lc := net.ListenConfig{}
		if l.md.mptcp {
			lc.SetMultipathTCP(true)
			l.logger.Debugf("mptcp enabled: %v", lc.MultipathTCP())
		}

		var ln net.Listener
		ln, err = lc.Listen(context.Background(), network, l.options.Addr)
		if err != nil {
			return
		}
		ln = tls.NewListener(ln, l.options.TLSConfig)

		ln = limiter_wrapper.WrapListener(l.options.Service, ln, l.options.TrafficLimiter)

		l.server = &dohServer{
			addr:      l.options.Addr,
			tlsConfig: l.options.TLSConfig,
			listener:  ln,
			server: &http.Server{
				Handler:      l,
				ReadTimeout:  l.md.readTimeout,
				WriteTimeout: l.md.writeTimeout,
			},
		}

	default:
		l.addr, err = net.ResolveUDPAddr("udp", l.options.Addr)
		if err != nil {
			return
		}

		network := "udp"
		if xnet.IsIPv4(l.options.Addr) {
			network = "udp4"
		}

		lc := net.ListenConfig{}
		if l.md.mptcp {
			lc.SetMultipathTCP(true)
			l.logger.Debugf("mptcp enabled: %v", lc.MultipathTCP())
		}

		var pc net.PacketConn
		pc, err = lc.ListenPacket(context.Background(), network, l.options.Addr)
		if err != nil {
			return
		}

		pc = limiter_wrapper.WrapPacketConn(
			pc,
			l.options.TrafficLimiter,
			traffic_limiter.ServiceLimitKey,
			limiter.ScopeOption(limiter.ScopeService),
			limiter.ServiceOption(l.options.Service),
			limiter.NetworkOption(network),
		)

		l.server = &dnsServer{
			server: &dns.Server{
				Net:          "udp",
				Addr:         l.options.Addr,
				PacketConn:   pc,
				Handler:      l,
				UDPSize:      l.md.readBufferSize,
				ReadTimeout:  l.md.readTimeout,
				WriteTimeout: l.md.writeTimeout,
			},
		}
	}

	if err != nil {
		return
	}

	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go func() {
		err := l.server.Serve()
		if err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()
	return
}

func (l *dnsListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.cqueue:
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

func (l *dnsListener) Close() error {
	return l.server.Shutdown()
}

func (l *dnsListener) Addr() net.Addr {
	return l.addr
}

func (l *dnsListener) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	b, err := m.Pack()
	if err != nil {
		l.logger.Error(err)
		return
	}
	if err := l.serve(w, b); err != nil {
		l.logger.Error(err)
	}
}

// Based on https://github.com/semihalev/sdns
func (l *dnsListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		buf, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if len(buf) == 0 || err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			l.logger.Errorf("unsupported media type: %s", ct)
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}

		buf, err = io.ReadAll(r.Body)
		if err != nil {
			l.logger.Error(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	default:
		l.logger.Errorf("method not allowd: %s", r.Method)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	mq := &dns.Msg{}
	if err := mq.Unpack(buf); err != nil {
		l.logger.Error(err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	w.Header().Set("Server", "SDNS")
	w.Header().Set("Content-Type", "application/dns-message")

	raddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if raddr == nil {
		raddr = &net.TCPAddr{}
	}
	if err := l.serve(&dohResponseWriter{raddr: raddr, ResponseWriter: w}, buf); err != nil {
		l.logger.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (l *dnsListener) serve(w ResponseWriter, msg []byte) (err error) {
	conn := &serverConn{
		r:      bytes.NewReader(msg),
		w:      w,
		laddr:  l.addr,
		closed: make(chan struct{}),
	}

	select {
	case l.cqueue <- conn:
	default:
		l.logger.Warnf("connection queue is full, client %s discarded", w.RemoteAddr())
		return errors.New("connection queue is full")
	}

	return conn.Wait()
}
