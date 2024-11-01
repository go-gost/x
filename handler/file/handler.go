package file

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("file", NewHandler)
}

type fileHandler struct {
	handler  http.Handler
	server   *http.Server
	ln       *singleConnListener
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
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

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
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
	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: r.RemoteAddr,
		Network:    "tcp",
		Host:       r.Host,
		Proto:      "http",
		HTTP: &xrecorder.HTTPRecorderObject{
			Host:   r.Host,
			Method: r.Method,
			Proto:  r.Proto,
			Scheme: r.URL.Scheme,
			URI:    r.RequestURI,
			Request: xrecorder.HTTPRequestRecorderObject{
				ContentLength: r.ContentLength,
				Header:        r.Header,
			},
		},
		Time: start,
	}
	ro.ClientIP, _, _ = net.SplitHostPort(r.RemoteAddr)

	log := h.options.Logger.WithFields(map[string]any{
		"remote": r.RemoteAddr,
	})

	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	defer func() {
		ro.Duration = time.Since(start)
		ro.HTTP.StatusCode = rw.statusCode
		ro.HTTP.Response = xrecorder.HTTPResponseRecorderObject{
			ContentLength: rw.contentLength,
			Header:        rw.Header(),
		}
		if err := ro.Record(context.Background(), h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s %s %s %d %d", r.Method, r.RequestURI, r.Proto, rw.statusCode, rw.contentLength)
	}()

	if auther := h.options.Auther; auther != nil {
		u, p, _ := r.BasicAuth()
		ro.ClientID = u
		if _, ok := auther.Authenticate(r.Context(), u, p); !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	h.handler.ServeHTTP(rw, r)
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

type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int64
}

func (w *responseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.contentLength += int64(n)
	return n, err
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
