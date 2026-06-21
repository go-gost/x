package service

import (
	"net"
	"net/http"
	"sync"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	xmetrics "github.com/go-gost/x/metrics"
)

const (
	// DefaultPath is the default HTTP path for the metrics endpoint.
	DefaultPath = "/metrics"
)

type options struct {
	path   string
	auther auth.Authenticator
}

// Option configures the metrics service.
type Option func(*options)

// PathOption sets the HTTP path for the metrics endpoint.
func PathOption(path string) Option {
	return func(o *options) {
		o.path = path
	}
}

// AutherOption sets the authenticator for the metrics endpoint.
func AutherOption(auther auth.Authenticator) Option {
	return func(o *options) {
		o.auther = auther
	}
}

type metricService struct {
	s        *http.Server
	ln       net.Listener
	cclose   chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewService creates a metrics Service that exposes Prometheus metrics over HTTP.
// It serves from the GOST custom registry rather than the default one so that
// process metrics are available on all platforms.
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
	if options.path == "" {
		options.path = DefaultPath
	}

	mux := http.NewServeMux()
	mux.Handle(options.path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS headers for browser-based access (e.g. Flutter dashboard)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if options.auther != nil {
			u, p, _ := r.BasicAuth()
			if _, ok := options.auther.Authenticate(r.Context(), u, p, auth.WithService("@metrics")); !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		reg := xmetrics.Registry()
		if reg == nil {
			reg = prometheus.DefaultRegisterer.(*prometheus.Registry)
		}
		promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}))
	return &metricService{
		s: &http.Server{
			Handler: mux,
		},
		ln:     ln,
		cclose: make(chan struct{}),
	}, nil
}

// Serve starts the metrics HTTP server and blocks until the listener is closed.
func (s *metricService) Serve() error {
	return s.s.Serve(s.ln)
}

// Addr returns the network address the metrics server is listening on.
func (s *metricService) Addr() net.Addr {
	return s.ln.Addr()
}

// Close stops the metrics HTTP server. It is safe to call multiple times.
func (s *metricService) Close() error {
	s.closeOnce.Do(func() {
		close(s.cclose)
		s.closeErr = s.s.Close()
	})
	return s.closeErr
}

// IsClosed reports whether the metrics service has been closed.
func (s *metricService) IsClosed() bool {
	select {
	case <-s.cclose:
		return true
	default:
		return false
	}
}
