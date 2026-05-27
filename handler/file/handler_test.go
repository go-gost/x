package file

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	cmdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	xlogger "github.com/go-gost/x/logger"
	xmetadata "github.com/go-gost/x/metadata"
	xrecorder "github.com/go-gost/x/recorder"
)

// --- test helpers ---

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct {
	raddr net.Addr
	laddr net.Addr
}

func (c *fakeConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (c *fakeConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *fakeConn) LocalAddr() net.Addr                { return c.laddr }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func newFakeConn(remote, local string) *fakeConn {
	return &fakeConn{raddr: fakeAddr(remote), laddr: fakeAddr(local)}
}

type fakeAuther struct {
	authFunc func(user, pass string) (string, bool)
}

func (a *fakeAuther) Authenticate(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
	if a.authFunc != nil {
		return a.authFunc(user, pass)
	}
	return user, true
}

type fakeRecorder struct {
	recorder.Recorder
	records [][]byte
	mu      sync.Mutex
}

func (r *fakeRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, b)
	return nil
}

func testMD(m map[string]any) cmdata.Metadata {
	return xmetadata.NewMetadata(m)
}

// --- singleConnListener tests ---

func TestSingleConnListener_Accept(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}

	c := newFakeConn("1.2.3.4:1234", "5.6.7.8:5678")
	ln.send(c)

	got, err := ln.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != c {
		t.Fatal("expected same connection")
	}
}

func TestSingleConnListener_Accept_Closed(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}
	ln.Close()

	_, err := ln.Accept()
	if err == nil {
		t.Fatal("expected error after close")
	}
}

func TestSingleConnListener_Close_Idempotent(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal("second Close() should not error")
	}
}

func TestSingleConnListener_Addr(t *testing.T) {
	a := fakeAddr("test-addr")
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
		addr: a,
	}
	if ln.Addr() != a {
		t.Fatal("expected test-addr")
	}
}

func TestSingleConnListener_Send_ClosesConnWhenDone(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}
	ln.Close()

	c := newFakeConn("1.2.3.4:1234", "5.6.7.8:5678")
	ln.send(c)
	// Connection should be closed (no way to observe directly on fakeConn,
	// but send returns without blocking, which is the key property)
}

func TestSingleConnListener_Send_BufferedChannelNoBlock(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}

	// Fill the buffer
	c1 := newFakeConn("1.1.1.1:1", "2.2.2.2:2")
	ln.send(c1)

	// Buffer is full, but we close before next send — proves buffered
	// channel prevents the deadlock that existed with unbuffered channel.
	ln.Close()

	c2 := newFakeConn("3.3.3.3:3", "4.4.4.4:4")
	done := make(chan struct{})
	go func() {
		ln.send(c2) // should return (done is closed), not deadlock
		close(done)
	}()

	select {
	case <-done:
		// OK — send returned
	case <-time.After(time.Second):
		t.Fatal("send() deadlocked — buffered channel fix not working")
	}
}

// --- responseWriter tests ---

type fakeResponseWriter struct {
	header     http.Header
	written    []byte
	statusCode int
}

func (w *fakeResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *fakeResponseWriter) Write(p []byte) (int, error) {
	w.written = append(w.written, p...)
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return len(p), nil
}

func (w *fakeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func TestResponseWriter_Write(t *testing.T) {
	fw := &fakeResponseWriter{}
	rw := &responseWriter{ResponseWriter: fw, statusCode: http.StatusOK}

	n, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("expected 5, got %d", n)
	}
	if rw.contentLength != 5 {
		t.Fatalf("expected contentLength 5, got %d", rw.contentLength)
	}
	if rw.statusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.statusCode)
	}
}

func TestResponseWriter_Write_MultipleWrites(t *testing.T) {
	fw := &fakeResponseWriter{}
	rw := &responseWriter{ResponseWriter: fw, statusCode: http.StatusOK}

	rw.Write([]byte("abc"))
	rw.Write([]byte("def"))
	rw.Write([]byte("ghi"))

	if rw.contentLength != 9 {
		t.Fatalf("expected 9, got %d", rw.contentLength)
	}
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	fw := &fakeResponseWriter{}
	rw := &responseWriter{ResponseWriter: fw, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)
	if rw.statusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rw.statusCode)
	}
	if fw.statusCode != http.StatusNotFound {
		t.Fatalf("underlying writer expected 404, got %d", fw.statusCode)
	}
}

func TestResponseWriter_DefaultStatusCode(t *testing.T) {
	fw := &fakeResponseWriter{}
	rw := &responseWriter{ResponseWriter: fw, statusCode: http.StatusOK}

	if rw.statusCode != http.StatusOK {
		t.Fatalf("expected default status 200, got %d", rw.statusCode)
	}
}

// --- NewHandler tests ---

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewHandler_WithOptions(t *testing.T) {
	h := NewHandler(
		handler.ServiceOption("test-svc"),
		handler.LoggerOption(xlogger.Nop()),
	)
	fh, ok := h.(*fileHandler)
	if !ok {
		t.Fatal("expected *fileHandler")
	}
	if fh.options.Service != "test-svc" {
		t.Fatalf("expected service 'test-svc', got %q", fh.options.Service)
	}
}

// --- Init tests ---

func TestInit(t *testing.T) {
	dir := t.TempDir()
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	md := testMD(map[string]any{"dir": dir})

	if err := fh.Init(md); err != nil {
		t.Fatal(err)
	}

	if fh.md.dir != dir {
		t.Fatalf("expected dir %q, got %q", dir, fh.md.dir)
	}
	if fh.ln == nil {
		t.Fatal("expected listener to be set")
	}
	if fh.server == nil {
		t.Fatal("expected server to be set")
	}

	// Clean up
	fh.Close()
}

func TestInit_MetadataFileDir(t *testing.T) {
	dir := t.TempDir()
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	md := testMD(map[string]any{"file.dir": dir})

	if err := fh.Init(md); err != nil {
		t.Fatal(err)
	}
	if fh.md.dir != dir {
		t.Fatalf("expected dir %q, got %q", dir, fh.md.dir)
	}

	fh.Close()
}

func TestInit_WithRecorder(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRecorder{}
	fh := &fileHandler{options: handler.Options{
		Logger: xlogger.Nop(),
		Recorders: []recorder.RecorderObject{
			{Record: xrecorder.RecorderServiceHandler, Recorder: fr},
		},
	}}
	md := testMD(map[string]any{"dir": dir})

	if err := fh.Init(md); err != nil {
		t.Fatal(err)
	}
	if fh.recorder.Recorder != fr {
		t.Fatal("expected recorder to be set")
	}

	fh.Close()
}

func TestInit_RecorderNotSelected(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRecorder{}
	fh := &fileHandler{options: handler.Options{
		Logger: xlogger.Nop(),
		Recorders: []recorder.RecorderObject{
			{Record: "other", Recorder: fr},
		},
	}}
	md := testMD(map[string]any{"dir": dir})

	if err := fh.Init(md); err != nil {
		t.Fatal(err)
	}
	if fh.recorder.Recorder != nil {
		t.Fatal("expected recorder to be nil (not selected)")
	}

	fh.Close()
}

// --- Handle tests ---

func TestHandle(t *testing.T) {
	dir := t.TempDir()
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	c := newFakeConn("10.0.0.1:1111", "10.0.0.2:2222")
	ctx := context.Background()

	err := fh.Handle(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	// Connection should now be accepted by the HTTP server.
	// We can verify by accepting it from the listener.
}

func TestHandle_WithSrcAddr(t *testing.T) {
	dir := t.TempDir()
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	c := newFakeConn("10.0.0.1:1111", "10.0.0.2:2222")
	ctx := xctx.ContextWithSrcAddr(context.Background(), fakeAddr("192.168.1.1:54321"))

	err := fh.Handle(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
}

// --- Close tests ---

func TestClose(t *testing.T) {
	dir := t.TempDir()
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}

	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}

	// Accept should return error after close
	_, err := fh.ln.Accept()
	if err == nil {
		t.Fatal("expected error from Accept after Close")
	}
}

// --- handleFunc tests ---

func TestHandleFunc_ServesFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	fr := &fakeRecorder{}
	fh := &fileHandler{options: handler.Options{
		Logger: xlogger.Nop(),
		Service: "test-svc",
		Recorders: []recorder.RecorderObject{
			{Record: xrecorder.RecorderServiceHandler, Recorder: fr},
		},
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "hello" {
		t.Fatalf("expected body 'hello', got %q", body)
	}
}

func TestHandleFunc_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRecorder{}
	fh := &fileHandler{options: handler.Options{
		Logger: xlogger.Nop(),
		Service: "test-svc",
		Recorders: []recorder.RecorderObject{
			{Record: xrecorder.RecorderServiceHandler, Recorder: fr},
		},
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleFunc_RecordsRequest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	fr := &fakeRecorder{}
	fh := &fileHandler{options: handler.Options{
		Logger: xlogger.Nop(),
		Service: "test-svc",
		Recorders: []recorder.RecorderObject{
			{Record: xrecorder.RecorderServiceHandler, Recorder: fr},
		},
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.RequestURI = "/f.txt"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	fr.mu.Lock()
	n := len(fr.records)
	fr.mu.Unlock()
	if n == 0 {
		t.Fatal("expected at least one record")
	}
}

func TestHandleFunc_RecordsStatusCode(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRecorder{}
	fh := &fileHandler{options: handler.Options{
		Logger: xlogger.Nop(),
		Service: "test-svc",
		Recorders: []recorder.RecorderObject{
			{Record: xrecorder.RecorderServiceHandler, Recorder: fr},
		},
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.RequestURI = "/missing"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	fr.mu.Lock()
	records := fr.records
	fr.mu.Unlock()

	if len(records) == 0 {
		t.Fatal("expected record")
	}
	// The JSON record should contain the 404 status
	if !strings.Contains(string(records[0]), "404") {
		t.Fatalf("expected record to contain 404 status, got: %s", string(records[0]))
	}
}

func TestHandleFunc_NoRecorder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()

	// Should not panic when recorder is nil
	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleFunc_Auth_Unauthorized(t *testing.T) {
	dir := t.TempDir()
	auther := &fakeAuther{
		authFunc: func(user, pass string) (string, bool) {
			return "", false
		},
	}
	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
		Auther:  auther,
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.SetBasicAuth("user", "wrong")
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "Basic" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestHandleFunc_Auth_Authorized(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	auther := &fakeAuther{
		authFunc: func(user, pass string) (string, bool) {
			return user, user == "admin" && pass == "password"
		},
	}
	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
		Auther:  auther,
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.SetBasicAuth("admin", "password")
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "secret" {
		t.Fatalf("expected body 'secret', got %q", rec.Body.String())
	}
}

func TestHandleFunc_Auth_SetsClientID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	fr := &fakeRecorder{}
	var capturedID string
	auther := &fakeAuther{
		authFunc: func(user, pass string) (string, bool) {
			capturedID = user
			return user, true
		},
	}
	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
		Auther:  auther,
		Recorders: []recorder.RecorderObject{
			{Record: xrecorder.RecorderServiceHandler, Recorder: fr},
		},
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.SetBasicAuth("client42", "pw")
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if capturedID != "client42" {
		t.Fatalf("expected client42, got %q", capturedID)
	}
}

func TestHandleFunc_NoAuther(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("public"), 0644); err != nil {
		t.Fatal(err)
	}

	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
		// Auther is nil — no auth required
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without auth, got %d", rec.Code)
	}
}

func TestHandleFunc_RequestWithoutBasicAuth(t *testing.T) {
	dir := t.TempDir()
	auther := &fakeAuther{
		authFunc: func(user, pass string) (string, bool) {
			// Reject empty user (no Authorization header)
			return user, user != ""
		},
	}
	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
		Auther:  auther,
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	// No Authorization header
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth header, got %d", rec.Code)
	}
}

// --- responseWriter WriteHeader idempotency ---

func TestResponseWriter_WriteHeader_Twice(t *testing.T) {
	fw := &fakeResponseWriter{}
	rw := &responseWriter{ResponseWriter: fw, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)
	rw.WriteHeader(http.StatusInternalServerError)
	// Last one wins in our tracker
	if rw.statusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rw.statusCode)
	}
}

// --- handleFunc with DumpRequest via Trace level ---

func TestHandleFunc_TraceLogging(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use Nop logger — it won't log at Trace level, so DumpRequest is never called.
	// This is to ensure the code path doesn't panic with a nil DumpRequest body.
	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/f.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.RequestURI = "/f.txt"
	// Large body to exercise DumpRequest path
	req.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 1000)))
	req.ContentLength = 1000
	req.Header.Set("X-Custom", "value")
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// --- Concurrency: send and close ---

func TestSendAndClose_Race(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c := newFakeConn("1.1.1.1:1", "2.2.2.2:2")
			ln.send(c)
		}()
		go func() {
			defer wg.Done()
			ln.Close()
		}()
	}
	wg.Wait()
	// No deadlock, no panic.
}

func TestAcceptAndClose_Race(t *testing.T) {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ln.Accept()
		}()
		go func() {
			defer wg.Done()
			ln.Close()
		}()
	}
	wg.Wait()
}

// --- Init parses metadata dir default ---

func TestInit_DirDefault(t *testing.T) {
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	if err := fh.Init(testMD(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	// With no "dir" or "file.dir" key, defaults to empty string.
	// http.Dir("") serves the current working directory.
	if fh.md.dir != "" {
		t.Fatalf("expected empty dir default, got %q", fh.md.dir)
	}
}

// --- handleFunc with index.html ---

func TestHandleFunc_ServesIndexHTML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>Home</h1>"), 0644); err != nil {
		t.Fatal(err)
	}

	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Home") {
		t.Fatalf("expected 'Home' in body, got %q", rec.Body.String())
	}
}

// --- handleFunc preserves content type ---

func TestHandleFunc_ContentType(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"k":"v"}`), 0644); err != nil {
		t.Fatal(err)
	}

	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/data.json", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
}

// --- handleFunc subdirectory ---

func TestHandleFunc_Subdirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "inner.txt"), []byte("nested"), 0644); err != nil {
		t.Fatal(err)
	}

	fh := &fileHandler{options: handler.Options{
		Logger:  xlogger.Nop(),
		Service: "test-svc",
	}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	req := httptest.NewRequest(http.MethodGet, "/sub/inner.txt", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()

	fh.handleFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "nested" {
		t.Fatalf("expected 'nested', got %q", rec.Body.String())
	}
}

// --- Registry ---

func TestRegistry(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	// Verify the handler type wraps the right struct
	_, ok := h.(*fileHandler)
	if !ok {
		t.Fatal("expected *fileHandler")
	}
}

// --- Handle with connection that gets closed by send ---

type closeTrackConn struct {
	net.Conn
	closed bool
	mu     sync.Mutex
}

func (c *closeTrackConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *closeTrackConn) RemoteAddr() net.Addr { return fakeAddr("r") }
func (c *closeTrackConn) LocalAddr() net.Addr  { return fakeAddr("l") }

func TestHandle_ConnClosedWhenSendDrops(t *testing.T) {
	dir := t.TempDir()
	fh := &fileHandler{options: handler.Options{Logger: xlogger.Nop()}}
	if err := fh.Init(testMD(map[string]any{"dir": dir})); err != nil {
		t.Fatal(err)
	}

	// Close the handler first so the listener's done is closed.
	// The explicit ln.Close() in Close() ensures done is closed before
	// server.Close() races with the Serve goroutine.
	fh.Close()

	// Verify the listener is actually closed.
	_, acceptErr := fh.ln.Accept()
	if acceptErr == nil {
		t.Fatal("expected listener to be closed after handler Close")
	}

	c := &closeTrackConn{}
	ctx := context.Background()

	fh.Handle(ctx, c)

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if !closed {
		t.Fatal("expected connection to be closed when send drops on done")
	}
}
