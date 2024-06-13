package pht

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/xid"
)

const (
	defaultBacklog        = 128
	defaultReadBufferSize = 32 * 1024
	defaultReadTimeout    = 10 * time.Second
)

type serverOptions struct {
	authorizePath  string
	pushPath       string
	pullPath       string
	backlog        int
	tlsEnabled     bool
	tlsConfig      *tls.Config
	readBufferSize int
	readTimeout    time.Duration
	mptcp          bool
	logger         logger.Logger
}

type ServerOption func(opts *serverOptions)

func PathServerOption(authorizePath, pushPath, pullPath string) ServerOption {
	return func(opts *serverOptions) {
		opts.authorizePath = authorizePath
		opts.pullPath = pullPath
		opts.pushPath = pushPath
	}
}

func BacklogServerOption(backlog int) ServerOption {
	return func(opts *serverOptions) {
		opts.backlog = backlog
	}
}

func TLSConfigServerOption(tlsConfig *tls.Config) ServerOption {
	return func(opts *serverOptions) {
		opts.tlsConfig = tlsConfig
	}
}

func EnableTLSServerOption(enable bool) ServerOption {
	return func(opts *serverOptions) {
		opts.tlsEnabled = enable
	}
}

func ReadBufferSizeServerOption(n int) ServerOption {
	return func(opts *serverOptions) {
		opts.readBufferSize = n
	}
}

func ReadTimeoutServerOption(timeout time.Duration) ServerOption {
	return func(opts *serverOptions) {
		opts.readTimeout = timeout
	}
}

func MPTCPServerOption(mptcp bool) ServerOption {
	return func(opts *serverOptions) {
		opts.mptcp = mptcp
	}
}

func LoggerServerOption(logger logger.Logger) ServerOption {
	return func(opts *serverOptions) {
		opts.logger = logger
	}
}

// TODO: remove stale clients from conns
type Server struct {
	addr        net.Addr
	httpServer  *http.Server
	http3Server *http3.Server
	cqueue      chan net.Conn
	conns       sync.Map
	closed      chan struct{}

	options serverOptions
}

func NewServer(addr string, opts ...ServerOption) *Server {
	var options serverOptions
	for _, opt := range opts {
		opt(&options)
	}
	if options.backlog <= 0 {
		options.backlog = defaultBacklog
	}
	if options.readBufferSize <= 0 {
		options.readBufferSize = defaultReadBufferSize
	}
	if options.readTimeout <= 0 {
		options.readTimeout = defaultReadTimeout
	}

	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: 30 * time.Second,
		},
		cqueue:  make(chan net.Conn, options.backlog),
		closed:  make(chan struct{}),
		options: options,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(options.authorizePath, s.handleAuthorize)
	mux.HandleFunc(options.pushPath, s.handlePush)
	mux.HandleFunc(options.pullPath, s.handlePull)
	s.httpServer.Handler = mux

	return s
}

func NewHTTP3Server(addr string, quicConfig *quic.Config, opts ...ServerOption) *Server {
	var options serverOptions
	for _, opt := range opts {
		opt(&options)
	}
	if options.backlog <= 0 {
		options.backlog = defaultBacklog
	}
	if options.readBufferSize <= 0 {
		options.readBufferSize = defaultReadBufferSize
	}
	if options.readTimeout <= 0 {
		options.readTimeout = defaultReadTimeout
	}

	s := &Server{
		http3Server: &http3.Server{
			Addr:       addr,
			TLSConfig:  options.tlsConfig,
			QUICConfig: quicConfig,
		},
		cqueue:  make(chan net.Conn, options.backlog),
		closed:  make(chan struct{}),
		options: options,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(options.authorizePath, s.handleAuthorize)
	mux.HandleFunc(options.pushPath, s.handlePush)
	mux.HandleFunc(options.pullPath, s.handlePull)
	s.http3Server.Handler = mux

	return s
}

func (s *Server) ListenAndServe() error {
	if s.http3Server != nil {
		network := "udp"
		if xnet.IsIPv4(s.http3Server.Addr) {
			network = "udp4"
		}
		addr, err := net.ResolveUDPAddr(network, s.http3Server.Addr)
		if err != nil {
			return err
		}

		s.addr = addr
		return s.http3Server.ListenAndServe()
	}

	network := "tcp"
	if xnet.IsIPv4(s.httpServer.Addr) {
		network = "tcp4"
	}

	lc := net.ListenConfig{}
	if s.options.mptcp {
		lc.SetMultipathTCP(true)
		s.options.logger.Debugf("mptcp enabled: %v", lc.MultipathTCP())
	}
	ln, err := lc.Listen(context.Background(), network, s.httpServer.Addr)
	if err != nil {
		s.options.logger.Error(err)
		return err
	}

	s.addr = ln.Addr()
	if s.options.tlsEnabled {
		s.httpServer.TLSConfig = s.options.tlsConfig
		ln = tls.NewListener(ln, s.options.tlsConfig)
	}

	return s.httpServer.Serve(ln)
}

func (s *Server) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-s.cqueue:
	case <-s.closed:
		err = http.ErrServerClosed
	}
	return
}

func (s *Server) Close() error {
	select {
	case <-s.closed:
		return http.ErrServerClosed
	default:
		close(s.closed)

		if s.http3Server != nil {
			return s.http3Server.Close()
		}
		return s.httpServer.Close()
	}
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.options.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		s.options.logger.Trace(string(dump))
	} else if s.options.logger.IsLevelEnabled(logger.DebugLevel) {
		s.options.logger.Debugf("%s %s", r.Method, r.RequestURI)
	}

	raddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if raddr == nil {
		raddr = &net.TCPAddr{}
	}

	// connection id
	cid := xid.New().String()

	c1, c2 := net.Pipe()
	c := &serverConn{
		Conn:       c1,
		localAddr:  s.addr,
		remoteAddr: raddr,
	}

	select {
	case s.cqueue <- c:
	default:
		c.Close()
		s.options.logger.Warnf("connection queue is full, client %s discarded", r.RemoteAddr)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	w.Write([]byte(fmt.Sprintf("token=%s", cid)))
	s.conns.Store(cid, c2)
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if s.options.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		s.options.logger.Trace(string(dump))
	} else if s.options.logger.IsLevelEnabled(logger.DebugLevel) {
		s.options.logger.Debugf("%s %s", r.Method, r.RequestURI)
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cid := r.Form.Get("token")
	v, ok := s.conns.Load(cid)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	conn := v.(net.Conn)

	br := bufio.NewReader(r.Body)
	data, err := br.ReadString('\n')
	if err != nil {
		if err != io.EOF {
			s.options.logger.Error(err)
			w.WriteHeader(http.StatusPartialContent)
		}
		conn.Close()
		s.conns.Delete(cid)
		return
	}

	data = strings.TrimSuffix(data, "\n")
	if len(data) == 0 {
		return
	}

	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		s.options.logger.Error(err)
		s.conns.Delete(cid)
		conn.Close()
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	if _, err := conn.Write(b); err != nil {
		s.options.logger.Error(err)
		s.conns.Delete(cid)
		conn.Close()
		w.WriteHeader(http.StatusGone)
	}
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	if s.options.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		s.options.logger.Trace(string(dump))
	} else if s.options.logger.IsLevelEnabled(logger.DebugLevel) {
		s.options.logger.Debugf("%s %s", r.Method, r.RequestURI)
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cid := r.Form.Get("token")
	v, ok := s.conns.Load(cid)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	conn := v.(net.Conn)

	w.WriteHeader(http.StatusOK)
	if fw, ok := w.(http.Flusher); ok {
		fw.Flush()
	}

	b := bufpool.Get(s.options.readBufferSize)
	defer bufpool.Put(b)

	for {
		conn.SetReadDeadline(time.Now().Add(s.options.readTimeout))
		n, err := conn.Read(b)
		if n > 0 {
			bw := bufio.NewWriter(w)
			bw.WriteString(base64.StdEncoding.EncodeToString(b[:n]))
			bw.WriteString("\n")
			if err := bw.Flush(); err != nil {
				return
			}
			if fw, ok := w.(http.Flusher); ok {
				fw.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				b[0] = '\n' // no data
				w.Write(b[:1])
			} else if errors.Is(err, io.EOF) {
				// server connection closed
			} else {
				if !errors.Is(err, io.ErrClosedPipe) {
					s.options.logger.Error(err)
				}
				s.conns.Delete(cid)
				conn.Close()
			}
			return
		}
	}
}
