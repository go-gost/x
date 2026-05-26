package api

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/api"
	"github.com/go-gost/x/registry"
)

var errHandlerNotInitialized = errors.New("api: handler not initialized")

func init() {
	registry.HandlerRegistry().Register("api", NewHandler)
}

// apiHandler is a handler that serves the GOST REST API over an inbound
// connection using the Gin framework.
type apiHandler struct {
	handler http.Handler
	md      metadata
	options handler.Options
}

// NewHandler creates an apiHandler with the given options.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &apiHandler{
		options: options,
	}
}

// Init initializes the handler with metadata, configuring the Gin engine
// and registering all API routes.
func (h *apiHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	api.Register(r, &api.Options{
		AccessLog:  h.md.accesslog,
		PathPrefix: h.md.pathPrefix,
		Auther:     h.options.Auther,
	})
	h.handler = r

	return
}

// Handle serves the API on the inbound connection. The connection is
// treated as a single-use HTTP listener: one connection is accepted, served,
// then the server shuts down gracefully.
func (h *apiHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	if h.handler == nil {
		return errHandlerNotInitialized
	}

	l := &singleConnListener{
		conn: make(chan net.Conn, 1),
	}
	l.send(conn)

	s := http.Server{
		Handler: h.handler,
	}

	// Serve blocks until the listener closes (after the single connection
	// is accepted). The connection goroutine may still be active.
	_ = s.Serve(l)

	return s.Shutdown(ctx)
}

// singleConnListener is a net.Listener that yields exactly one connection
// from a buffered channel, then returns net.ErrClosed on subsequent accepts.
type singleConnListener struct {
	conn chan net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if conn, ok := <-l.conn; ok {
		return conn, nil
	}
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func (l *singleConnListener) send(conn net.Conn) {
	l.conn <- conn
	close(l.conn)
}
