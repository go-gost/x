package api

import (
	"context"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/api"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("api", NewHandler)
}

type apiHandler struct {
	handler http.Handler
	md      metadata
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &apiHandler{
		options: options,
	}
}

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

func (h *apiHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	l := &singleConnListener{
		conn: make(chan net.Conn, 1),
	}
	l.send(conn)

	s := http.Server{
		Handler: h.handler,
	}
	s.Serve(l)

	return s.Shutdown(ctx)
}

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
