package file

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("file", NewHandler)
}

type fileHandler struct {
	handler http.Handler
	server  *http.Server
	ln      *singleConnListener
	md      metadata
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &fileHandler{
		options: options,
	}
}

func (h *fileHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	h.handler = http.FileServer(http.Dir(h.md.dir))
	h.server = &http.Server{
		Handler: http.HandlerFunc(h.handleFunc),
	}

	h.ln = &singleConnListener{
		conn: make(chan net.Conn),
		done: make(chan struct{}),
	}
	go h.server.Serve(h.ln)

	return
}

func (h *fileHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	}).Infof("%s - %s", conn.RemoteAddr(), conn.LocalAddr())

	h.ln.send(conn)

	return nil
}

func (h *fileHandler) Close() error {
	return h.server.Close()
}

func (h *fileHandler) handleFunc(w http.ResponseWriter, r *http.Request) {
	if auther := h.options.Auther; auther != nil {
		u, p, _ := r.BasicAuth()
		if _, ok := auther.Authenticate(r.Context(), u, p); !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	log := h.options.Logger
	start := time.Now()

	h.handler.ServeHTTP(w, r)

	log = log.WithFields(map[string]any{
		"remote":   r.RemoteAddr,
		"duration": time.Since(start),
	})
	log.Infof("%s %s", r.Method, r.RequestURI)
}

type singleConnListener struct {
	conn chan net.Conn
	addr net.Addr
	done chan struct{}
	mu   sync.Mutex
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conn:
		return conn, nil

	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	select {
	case <-l.done:
	default:
		close(l.done)
	}

	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

func (l *singleConnListener) send(conn net.Conn) {
	select {
	case l.conn <- conn:
	case <-l.done:
		return
	}
}
