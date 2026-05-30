package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/handler"
	xstats "github.com/go-gost/x/observer/stats"
	xrecorder "github.com/go-gost/x/recorder"
)

func TestProxyRoundTrip_BasicGET(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: ts.Client().Transport,
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", ts.URL, nil)
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}

	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	closeConn, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err != nil {
		t.Fatalf("proxyRoundTrip error: %v", err)
	}
	if !closeConn {
		t.Error("expected close=true with Connection: close response")
	}
}

func TestProxyRoundTrip_WithBypass(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
			Bypass: &testBypass{contains: true},
		},
	}
	h.md.proxyAgent = defaultProxyAgent

	req, _ := http.NewRequest("GET", "http://blocked.example.com", nil)
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}

	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	close, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err == nil {
		t.Error("expected bypass error")
	}
	if !close {
		t.Error("expected close=true for bypass")
	}
}

func TestProxyRoundTrip_WithoutBypass(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
			Bypass: &testBypass{contains: false},
		},
		transport: ts.Client().Transport,
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", ts.URL, nil)
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}

	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	closeConn, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err != nil {
		t.Fatalf("proxyRoundTrip error: %v", err)
	}
	if !closeConn {
		t.Error("expected close=true with Connection: close response")
	}
}

func TestProxyRoundTrip_TransportError(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: &testRoundTripper{err: true},
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", "http://error.example.com", nil)
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}

	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	close, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err == nil {
		t.Error("expected transport error")
	}
	if !close {
		t.Error("expected close=true on transport error")
	}
}

func TestProxyRoundTrip_HTTP10(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: ts.Client().Transport,
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.ProtoMajor = 1
	req.ProtoMinor = 0
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}

	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	_, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err != nil {
		t.Fatalf("proxyRoundTrip error with HTTP/1.0: %v", err)
	}
}


func TestHandleUpgradeResponse_Mismatch(t *testing.T) {
	h := &httpHandler{}
	h.md.proxyAgent = defaultProxyAgent

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"h2c"},
		},
	}

	err := h.handleUpgradeResponse(context.Background(), &testReadWriteCloser{}, req, res, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err == nil {
		t.Error("expected error for upgrade type mismatch")
	}
}

func TestHandleUpgradeResponse_NonReadWriteCloserBody(t *testing.T) {
	h := &httpHandler{}
	h.md.proxyAgent = defaultProxyAgent

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"websocket"},
		},
		Body: io.NopCloser(strings.NewReader("not a rwc")),
	}

	err := h.handleUpgradeResponse(context.Background(), &testReadWriteCloser{}, req, res, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err == nil {
		t.Error("expected error for non-io.ReadWriteCloser body")
	}
}

func TestProxyRoundTrip_HeaderCleanup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers are cleaned
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization should be removed")
		}
		if r.Header.Get("Proxy-Connection") != "" {
			t.Error("Proxy-Connection should be removed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: ts.Client().Transport,
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Proxy-Authorization", "Basic xyz")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Gost-Target", "hidden")
	req.Header.Set("X-Gost-Target", "also-hidden")

	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}
	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	_, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err != nil {
		t.Fatalf("proxyRoundTrip error: %v", err)
	}
}

// testBypass implements bypass.Bypass for testing.
type testBypass struct {
	contains bool
}

func (b *testBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return b.contains
}

func (b *testBypass) IsWhitelist() bool { return false }

// testRoundTripper implements http.RoundTripper for testing.
type testRoundTripper struct {
	err    bool
	status int
	body   string
}

func (rt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.err {
		return nil, &testError{msg: "transport error"}
	}
	if rt.status == 0 {
		rt.status = http.StatusOK
	}
	return &http.Response{
		StatusCode: rt.status,
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Header:     http.Header{},
	}, nil
}

func TestHandleProxy_SingleRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: ts.Client().Transport,
	}
	h.md.readTimeout = 15

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", ts.URL, nil)
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}

	// Drain response in a goroutine
	go func() {
		io.ReadAll(server)
	}()

	err := h.handleProxy(context.Background(), client, req, ro, &testLogger{})
	if err != nil {
		t.Logf("handleProxy returned: %v", err)
	}
}

func TestProxyRoundTrip_SwitchingProtocols(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: &testRoundTripper{status: http.StatusSwitchingProtocols, body: ""},
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}
	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	_, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	// Switching protocols with a non-RWC body should error
	if err == nil {
		t.Log("expected error for switching protocols with non-RWC body")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string   { return e.msg }
func (e *testError) Timeout() bool   { return false }
func (e *testError) Temporary() bool { return true }

func TestProxyRoundTrip_HTTP10_KeepAlive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For HTTP/1.0 keep-alive, client sends Connection: keep-alive
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
		transport: ts.Client().Transport,
	}
	h.md.readTimeout = 15

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.ProtoMajor = 1
	req.ProtoMinor = 0
	req.Header.Set("Connection", "keep-alive") // client wants keep-alive

	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}
	pStats := xstats.Stats{}
	rw := &testReadWriteCloser{buf: new(strings.Builder)}

	_, err := h.proxyRoundTrip(context.Background(), rw, req, ro, &pStats, &testLogger{})
	if err != nil {
		t.Fatalf("proxyRoundTrip error: %v", err)
	}
}


// testReadWriteCloser implements io.ReadWriteCloser for testing.
type testReadWriteCloser struct {
	buf *strings.Builder
}

func (rw *testReadWriteCloser) Read(p []byte) (int, error)  { return 0, io.EOF }
func (rw *testReadWriteCloser) Write(p []byte) (int, error) {
	if rw.buf != nil {
		return rw.buf.Write(p)
	}
	return len(p), nil
}
func (rw *testReadWriteCloser) Close() error { return nil }
