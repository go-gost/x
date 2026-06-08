// Package file provides a static file-serving handler for GOST.
// It serves files from a configured directory over HTTP via the GOST proxy chain.
package file

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
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

// NewHandler creates a static file-serving handler. It registers as "file" in the
// handler registry and serves files from the directory specified by the "file.dir"
// or "dir" metadata key.
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

	if h.md.dir != "" {
		if info, err := os.Stat(h.md.dir); err != nil {
			return fmt.Errorf("file handler: directory %q: %w", h.md.dir, err)
		} else if !info.IsDir() {
			return fmt.Errorf("file handler: %q is not a directory", h.md.dir)
		}
	}

	fs := http.FileServer(http.Dir(h.md.dir))
	h.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if !h.md.put {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			h.handlePUT(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
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
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
		addr: &listenerAddr{},
	}
	go h.server.Serve(h.ln)

	return
}

func (h *fileHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	var clientAddr string
	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		clientAddr = srcAddr.String()
	}

	remoteAddr := conn.RemoteAddr()
	localAddr := conn.LocalAddr()

	h.options.Logger.WithFields(map[string]any{
		"client": clientAddr,
		"remote": remoteAddr.String(),
		"local":  localAddr.String(),
	}).Infof("%s - %s", remoteAddr, localAddr)

	h.ln.send(conn)

	return nil
}

func (h *fileHandler) Close() error {
	if h.ln != nil {
		h.ln.Close()
	}
	return h.server.Close()
}

func (h *fileHandler) handlePUT(w http.ResponseWriter, r *http.Request) {
	// Reject path traversal attempts.
	target := path.Clean(r.URL.Path)
	if strings.Contains(target, "..") || !strings.HasPrefix(target, "/") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	dest := filepath.Join(h.md.dir, filepath.FromSlash(target))
	// Verify the resolved path is within the base directory.
	base, err := filepath.Abs(h.md.dir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(absDest, base) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := os.MkdirAll(filepath.Dir(absDest), 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	f, err := os.Create(absDest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := io.Copy(f, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
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

	log := h.options.Logger.WithFields(map[string]any{
		"remote": r.RemoteAddr,
	})

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Trace(string(dump))
	}

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
		if _, ok := auther.Authenticate(r.Context(), u, p, auth.WithService(ro.Service)); !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	if h.handler != nil {
		h.handler.ServeHTTP(rw, r)
	}
}

type listenerAddr struct{}

func (a *listenerAddr) Network() string { return "file" }
func (a *listenerAddr) String() string  { return "file" }

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
	case <-l.done:
		conn.Close()
		return
	default:
	}
	select {
	case l.conn <- conn:
	case <-l.done:
		conn.Close()
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

// Unwrap returns the underlying ResponseWriter, allowing http.ResponseController
// to discover optional interfaces (Flusher, Hijacker, etc.) on the wrapped writer.
func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
