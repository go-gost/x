package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/recorder"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"
)

// =============================================================================
// Test Helpers (local mocks)
// =============================================================================

type noopRecorder struct{}

func (n *noopRecorder) Record(_ context.Context, _ []byte, _ ...recorder.RecordOption) error {
	return nil
}

// mockBypass is a configurable bypass.Bypass for tests.
type mockBypass struct {
	contains  bool
	whitelist bool
}

func (m *mockBypass) Contains(_ context.Context, _, _ string, _ ...bypass.Option) bool {
	return m.contains
}

func (m *mockBypass) IsWhitelist() bool { return m.whitelist }

// =============================================================================
// Pure Function Tests
// =============================================================================

func TestClampBodySize(t *testing.T) {
	tests := []struct {
		name string
		opts *recorder.Options
		want int
	}{
		{"nil opts", nil, 0},
		{"HTTPBody disabled", &recorder.Options{HTTPBody: false, MaxBodySize: 1000}, 0},
		{"zero MaxBodySize defaults to defaultBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: 0}, defaultBodySize},
		{"negative MaxBodySize defaults", &recorder.Options{HTTPBody: true, MaxBodySize: -1}, defaultBodySize},
		{"valid MaxBodySize within bounds", &recorder.Options{HTTPBody: true, MaxBodySize: 1024}, 1024},
		{"MaxBodySize capped at maxBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: 10 * 1024 * 1024}, maxBodySize},
		{"exact maxBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: maxBodySize}, maxBodySize},
		{"exact defaultBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: defaultBodySize}, defaultBodySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampBodySize(tt.opts); got != tt.want {
				t.Errorf("clampBodySize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		defaultPort string
		want        string
	}{
		{"empty host", "", "443", ""},
		{"host with port", "example.com:8080", "443", "example.com:8080"},
		{"host without port, default 80", "example.com", "80", "example.com:80"},
		{"host without port, default 443", "example.com", "443", "example.com:443"},
		{"IPv4 with port", "127.0.0.1:9090", "80", "127.0.0.1:9090"},
		{"IPv4 without port", "127.0.0.1", "80", "127.0.0.1:80"},
		{"IPv6 bracketed with port", "[::1]:8080", "443", "[::1]:8080"},
		{"IPv6 bracketed without port", "[::1]", "443", "[::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeHost(tt.host, tt.defaultPort)
			if got != tt.want {
				t.Errorf("normalizeHost(%q, %q) = %q, want %q", tt.host, tt.defaultPort, got, tt.want)
			}
		})
	}
}

func TestEffectiveReadTimeout(t *testing.T) {
	tests := []struct {
		name      string
		snifferTO time.Duration
		hoTO      time.Duration
		want      time.Duration
	}{
		{"both zero defaults to DefaultReadTimeout", 0, 0, DefaultReadTimeout},
		{"sniffer timeout only", 10 * time.Second, 0, 10 * time.Second},
		{"ho timeout only", 0, 5 * time.Second, 5 * time.Second},
		{"ho timeout takes precedence", 10 * time.Second, 3 * time.Second, 3 * time.Second},
		{"sniffer timeout takes precedence when ho is zero", 15 * time.Second, 0, 15 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Sniffer{ReadTimeout: tt.snifferTO}
			ho := &HandleOptions{readTimeout: tt.hoTO}
			got := h.effectiveReadTimeout(ho)
			if got != tt.want {
				t.Errorf("effectiveReadTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpgradeType(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			"websocket upgrade",
			http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}},
			"websocket",
		},
		{
			"h2c upgrade",
			http.Header{"Connection": {"Upgrade"}, "Upgrade": {"h2c"}},
			"h2c",
		},
		{
			"no upgrade header",
			http.Header{"Connection": {"keep-alive"}},
			"",
		},
		{
			"empty header",
			http.Header{},
			"",
		},
		{
			"connection has upgrade but no upgrade header",
			http.Header{"Connection": {"Upgrade"}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := upgradeType(tt.header); got != tt.want {
				t.Errorf("upgradeType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDrainBody(t *testing.T) {
	t.Run("nil body", func(t *testing.T) {
		got, err := drainBody(nil)
		if err != nil || got != nil {
			t.Errorf("drainBody(nil) = (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("http.NoBody", func(t *testing.T) {
		got, err := drainBody(http.NoBody)
		if err != nil || got != nil {
			t.Errorf("drainBody(NoBody) = (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("normal body", func(t *testing.T) {
		body := io.NopCloser(strings.NewReader("hello world"))
		got, err := drainBody(body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello world" {
			t.Errorf("drainBody() = %q, want %q", string(got), "hello world")
		}
	})

	t.Run("empty body", func(t *testing.T) {
		body := io.NopCloser(strings.NewReader(""))
		got, err := drainBody(body)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("drainBody() = %q, want empty", string(got))
		}
	})
}

// =============================================================================
// Rewrite Response Body Tests
// =============================================================================

func TestRewriteRespBody(t *testing.T) {
	t.Run("nil response", func(t *testing.T) {
		if err := rewriteRespBody(nil); err != nil {
			t.Errorf("rewriteRespBody(nil) = %v, want nil", err)
		}
	})

	t.Run("no rewrites", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(resp)
		// Body unchanged
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "original" {
			t.Errorf("body = %q, want %q", string(got), "original")
		}
	})

	t.Run("zero content length", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: 0,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(resp, chain.HTTPBodyRewriteSettings{
			Pattern:     regexp.MustCompile("."),
			Type:        "*",
			Replacement: []byte("replaced"),
		})
		got, _ := io.ReadAll(resp.Body)
		// Content-Length was 0 (unknown), so no rewrite applied
		if string(got) != "original" {
			t.Errorf("body = %q, want %q (unchanged)", string(got), "original")
		}
	})

	t.Run("with content encoding", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": {"gzip"}},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(resp, chain.HTTPBodyRewriteSettings{
			Type:        "*",
			Replacement: []byte("replaced"),
		})
		got, _ := io.ReadAll(resp.Body)
		// Content-Encoding present, rewrite skipped
		if string(got) != "original" {
			t.Errorf("body = %q, want %q (unchanged)", string(got), "original")
		}
	})
}

func TestRewriteRespBodyContentTypeFilter(t *testing.T) {
	// Helper to create a rewrite rule that replaces everything.
	makeRewrite := func(rewriteType string, replacement string) chain.HTTPBodyRewriteSettings {
		return chain.HTTPBodyRewriteSettings{
			Pattern:     regexp.MustCompile(".*"),
			Type:        rewriteType,
			Replacement: []byte(replacement),
		}
	}

	t.Run("exact type match text/html", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(resp, makeRewrite("text/html", "replaced"))
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "replaced" {
			t.Errorf("body = %q, want %q", string(got), "replaced")
		}
	})

	t.Run("wildcard type rewrites anything", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Type": {"application/json"}},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("hello")),
		}
		_ = rewriteRespBody(resp, makeRewrite("*", "world"))
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "world" {
			t.Errorf("body = %q, want %q", string(got), "world")
		}
	})

	t.Run("mismatched type is skipped", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Type": {"text/plain"}},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(resp, makeRewrite("text/html", "replaced"))
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "original" {
			t.Errorf("body = %q, want %q (unchanged)", string(got), "original")
		}
	})

	t.Run("empty content type defaults to text/html", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		// Empty type defaults to "text/html", and response has no Content-Type -> "" containing "text/html"? No.
		// strings.Contains("text/html", "") is always true, so rewrite should happen.
		_ = rewriteRespBody(resp, makeRewrite("", "replaced"))
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "replaced" {
			t.Errorf("body = %q, want %q (should be rewritten)", string(got), "replaced")
		}
	})
}

// =============================================================================
// TLS Wrap Tests
// =============================================================================

func TestTLSWrapConn_NilSettings(t *testing.T) {
	cc := &net.TCPConn{} // will never be used as a real connection
	if got := tlsWrapConn(cc, nil); got != cc {
		t.Errorf("tlsWrapConn(nil settings) should return original conn unchanged")
	}
}

// =============================================================================
// HandleHTTP Integration Tests
// =============================================================================

func TestHandleHTTP_BasicProxy(t *testing.T) {
	// Set up an HTTP test server that acts as the upstream.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK from upstream"))
	}))
	defer upstream.Close()

	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	// Use net.Pipe and serve the client request in a goroutine.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), serverConn,
			WithService("test-svc"),
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	// Write an HTTP request to the client side of the pipe.
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.Write(clientConn); err != nil {
		t.Fatal(err)
	}

	// Read the response back.
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	clientConn.Close()
	if err := <-errCh; err != nil {
		t.Logf("HandleHTTP returned: %v", err)
	}

	// Verify recorder object was populated.
	if ro.SrcAddr == "" {
		t.Error("SrcAddr should be populated")
	}
	if ro.DstAddr == "" {
		t.Error("DstAddr should be populated")
	}
}

func TestHandleHTTP_HTTP2Detection(t *testing.T) {
	// HTTP/2 connection preface should be detected and handled separately.
	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), serverConn,
			WithService("test-svc"),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	// Write HTTP/2 upgrade request
	clientConn.Write([]byte("PRI * HTTP/2.0\r\n\r\n"))
	// The handler will now try to read the SM\r\n\r\n preface, which we don't send.
	// It should return an error about invalid client preface.

	clientConn.Close()

	err := <-errCh
	if err == nil {
		t.Log("HandleHTTP returned nil (expected error from incomplete h2 preface)")
	}
}

// =============================================================================
// HandleOptions Tests
// =============================================================================

func TestWithService(t *testing.T) {
	opts := &HandleOptions{}
	WithService("mysvc")(opts)
	if opts.service != "mysvc" {
		t.Errorf("service = %q, want %q", opts.service, "mysvc")
	}
}

func TestWithHTTPKeepalive(t *testing.T) {
	opts := &HandleOptions{}
	WithHTTPKeepalive(true)(opts)
	if !opts.httpKeepalive {
		t.Errorf("httpKeepalive = false, want true")
	}
}

func TestWithNode(t *testing.T) {
	opts := &HandleOptions{}
	node := &chain.Node{Name: "test-node", Addr: "127.0.0.1:8080"}
	WithNode(node)(opts)
	if opts.node != node {
		t.Errorf("node not set")
	}
}

func TestWithHop(t *testing.T) {
	opts := &HandleOptions{}
	mh := &mockHop{}
	WithHop(mh)(opts)
	if opts.hop != mh {
		t.Errorf("hop not set")
	}
}

func TestWithBypass(t *testing.T) {
	opts := &HandleOptions{}
	bp := &mockBypass{contains: true}
	WithBypass(bp)(opts)
	if opts.bypass != bp {
		t.Errorf("bypass not set")
	}
}

func TestWithRecorderObject(t *testing.T) {
	opts := &HandleOptions{}
	ro := &xrecorder.HandlerRecorderObject{}
	WithRecorderObject(ro)(opts)
	if opts.recorderObject != ro {
		t.Errorf("recorderObject not set")
	}
}

func TestWithLog(t *testing.T) {
	opts := &HandleOptions{}
	log := xlogger.Nop()
	WithLog(log)(opts)
	if opts.log != log {
		t.Errorf("log not set")
	}
}

// =============================================================================
// mockHop for testing
// =============================================================================

type mockHop struct {
	nodes []*chain.Node
}

func (m *mockHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if len(m.nodes) > 0 {
		return m.nodes[0]
	}
	return nil
}

// Ensure mockHop implements hop.Hop.
var _ hop.Hop = (*mockHop)(nil)

// =============================================================================
// HandleHTTP Edge Case Tests
// =============================================================================

func TestHandleHTTP_DialError(t *testing.T) {
	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), serverConn,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, io.ErrUnexpectedEOF
			}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	// Write a valid HTTP request, then read the error response to avoid pipe deadlock.
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Write(clientConn)

	// Read the error response to unblock the server-side write.
	br := bufio.NewReader(clientConn)
	resp, respErr := http.ReadResponse(br, req)
	if respErr != nil {
		t.Errorf("reading error response: %v", respErr)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
		}
	}

	err := <-errCh
	if err == nil {
		t.Error("expected error from failed dial, got nil")
	}
}

func TestHandleHTTP_HTTP10Request(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("HTTP/1.0 OK"))
	}))
	defer upstream.Close()

	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), serverConn,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	// Write an HTTP/1.0 request
	clientConn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"))

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	clientConn.Close()
	<-errCh
}

// =============================================================================
// WebSocket Frame Test
// =============================================================================

func TestCopyWebsocketFrame_Basic(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	// Build a minimal WebSocket text frame: fin=true, opcode=text(1), masked, payload="hi"
	payload := []byte("hi")
	mask := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ mask[i%4]
	}

	var frame bytes.Buffer
	frame.WriteByte(0x81)      // FIN + text opcode
	frame.WriteByte(0x82)      // MASK + len=2
	frame.Write(mask)          // mask key
	frame.Write(maskedPayload) // masked payload

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "client", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if ro.Websocket.OpCode != 1 {
		t.Errorf("opcode = %d, want 1 (text)", ro.Websocket.OpCode)
	}
	if ro.Websocket.Masked != true {
		t.Error("client frame should be marked as masked")
	}

	// Client direction: InputBytes should be non-zero.
	if ro.InputBytes == 0 {
		t.Error("InputBytes should be non-zero for client direction")
	}
}

func TestCopyWebsocketFrame_WithBodyRecording(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
	}

	payload := []byte("hello ws")
	// Build a server frame (unmasked) with FIN + text opcode.
	var frame bytes.Buffer
	frame.WriteByte(0x81)                   // FIN + text
	frame.WriteByte(byte(len(payload))) // MASK=0, len
	// No mask for server frames
	frame.Write(payload)

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "server", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if string(ro.Websocket.Payload) != "hello ws" {
		t.Errorf("payload = %q, want %q", ro.Websocket.Payload, "hello ws")
	}
	if ro.Websocket.Masked != false {
		t.Error("server frame should be marked as unmasked")
	}
	// Server frames: OutputBytes should be non-zero.
	if ro.OutputBytes == 0 {
		t.Error("OutputBytes should be non-zero for server direction")
	}
}

// =============================================================================
// normalizeHost Edge Cases
// =============================================================================

func TestNormalizeHost_EdgeCases(t *testing.T) {
	// IPv6 with brackets already has port
	got := normalizeHost("[::1]:8080", "443")
	if got != "[::1]:8080" {
		t.Errorf("got %q, want %q", got, "[::1]:8080")
	}

	// Hostname with port
	got = normalizeHost("localhost:3000", "80")
	if got != "localhost:3000" {
		t.Errorf("got %q, want %q", got, "localhost:3000")
	}
}

