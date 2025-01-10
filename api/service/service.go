package service

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/service"
	"github.com/go-gost/x/api"
)

type options struct {
	accessLog  bool
	pathPrefix string
	auther     auth.Authenticator
}

type Option func(*options)

func PathPrefixOption(pathPrefix string) Option {
	return func(o *options) {
		o.pathPrefix = pathPrefix
	}
}

func AccessLogOption(enable bool) Option {
	return func(o *options) {
		o.accessLog = enable
	}
}

func AutherOption(auther auth.Authenticator) Option {
	return func(o *options) {
		o.auther = auther
	}
}

type server struct {
	s      *http.Server
	ln     net.Listener
	cclose chan struct{}
}

func NewService(network, addr string, opts ...Option) (service.Service, error) {
	if network == "" {
		network = "tcp"
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	var options options
	for _, opt := range opts {
		opt(&options)
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	api.Register(r, &api.Options{
		AccessLog:  options.accessLog,
		PathPrefix: options.pathPrefix,
		Auther:     options.auther,
	})

	return &server{
		s: &http.Server{
			Handler: r,
		},
		ln:     ln,
		cclose: make(chan struct{}),
	}, nil
}

func (s *server) Serve() error {
	return s.s.Serve(s.ln)
}

func (s *server) Addr() net.Addr {
	return s.ln.Addr()
}

func (s *server) Close() error {
	return s.s.Close()
}

func (s *server) IsClosed() bool {
	select {
	case <-s.cclose:
		return true
	default:
		return false
	}
}
