package forwarder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/rewriter"
	"github.com/klauspost/compress/zstd"
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

// compressTestData compresses data with the given encoding for test purposes.
func compressTestData(data []byte, encoding string) []byte {
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		w := gzip.NewWriter(&buf)
		w.Write(data)
		w.Close()
	case "deflate":
		w := zlib.NewWriter(&buf)
		w.Write(data)
		w.Close()
	case "br":
		w := brotli.NewWriter(&buf)
		w.Write(data)
		w.Close()
	case "zstd":
		w, _ := zstd.NewWriter(&buf)
		w.Write(data)
		w.Close()
	default:
		return data
	}
	return buf.Bytes()
}

// =============================================================================
// Pure Function Tests
// =============================================================================

func TestRewriteReqBody(t *testing.T) {
	hello := []byte("hello world")

	tests := []struct {
		name     string
		req      *http.Request
		rewrites []chain.HTTPBodyRewriteSettings
		wantBody string
		wantCL   int64
	}{
		{
			name: "nil request",
		},
		{
			name: "no rewrites",
			req: &http.Request{
				Body:          io.NopCloser(bytes.NewReader(hello)),
				ContentLength: int64(len(hello)),
			},
			wantBody: "hello world",
			wantCL:   11,
		},
		{
			name: "nil body",
			req: &http.Request{
				Body:          nil,
				ContentLength: 11,
			},
			rewrites: []chain.HTTPBodyRewriteSettings{
				{Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
			},
			wantBody: "",
			wantCL:   0,
		},
		{
			name: "zero content length",
			req: &http.Request{
				Body:          io.NopCloser(bytes.NewReader(hello)),
				ContentLength: 0,
			},
			rewrites: []chain.HTTPBodyRewriteSettings{
				{Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
			},
			wantBody: "hi world",
			wantCL:   8,
		},
		{
			name: "content type does not match default text/html",
			req: &http.Request{
				Body:          io.NopCloser(bytes.NewReader(hello)),
				ContentLength: int64(len(hello)),
				Header:        http.Header{"Content-Type": {"text/plain"}},
			},
			rewrites: []chain.HTTPBodyRewriteSettings{
				{Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
			},
			wantBody: "hello world",
			wantCL:   11,
		},
		{
			name: "content type match replacement",
			req: &http.Request{
				Body:          io.NopCloser(bytes.NewReader(hello)),
				ContentLength: int64(len(hello)),
				Header:        http.Header{"Content-Type": {"text/html"}},
			},
			rewrites: []chain.HTTPBodyRewriteSettings{
				{Type: "text/html", Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
			},
			wantBody: "hi world",
			wantCL:   8,
		},
		{
			name: "wildcard type matches everything",
			req: &http.Request{
				Body:          io.NopCloser(bytes.NewReader(hello)),
				ContentLength: int64(len(hello)),
				Header:        http.Header{"Content-Type": {"application/json"}},
			},
			rewrites: []chain.HTTPBodyRewriteSettings{
				{Type: "*", Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
			},
			wantBody: "hi world",
			wantCL:   8,
		},
		{
			name: "multiple rewrites applied in order",
			req: &http.Request{
				Body:          io.NopCloser(bytes.NewReader(hello)),
				ContentLength: int64(len(hello)),
				Header:        http.Header{"Content-Type": {"text/html"}},
			},
			rewrites: []chain.HTTPBodyRewriteSettings{
				{Type: "text/html", Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
				{Type: "text/html", Pattern: regexp.MustCompile("world"), Replacement: []byte("there")},
			},
			wantBody: "hi there",
			wantCL:   8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.req != nil {
				_ = rewriteReqBody(context.Background(), tt.req, tt.rewrites...)
				if tt.req.Body != nil {
					body, _ := io.ReadAll(tt.req.Body)
					tt.req.Body.Close()
					if string(body) != tt.wantBody {
						t.Errorf("body = %q, want %q", string(body), tt.wantBody)
					}
				} else if tt.wantBody != "" {
					t.Errorf("body = nil, want %q", tt.wantBody)
				}
				if tt.req.ContentLength != tt.wantCL {
					t.Errorf("ContentLength = %d, want %d", tt.req.ContentLength, tt.wantCL)
				}
			} else {
				_ = rewriteReqBody(context.Background(), nil) // should not panic
			}
		})
	}
}
func TestRewriteReqBody_Gzip(t *testing.T) {
	t.Run("gzip content-encoding rewrite", func(t *testing.T) {
		hello := []byte("hello world")
		gzipHello := compressTestData(hello, "gzip")
		req := &http.Request{
			Body:          io.NopCloser(bytes.NewReader(gzipHello)),
			ContentLength: int64(len(gzipHello)),
			Header:        http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/html"}},
		}
		_ = rewriteReqBody(context.Background(), req, []chain.HTTPBodyRewriteSettings{
			{Type: "*", Pattern: regexp.MustCompile("hello"), Replacement: []byte("hi")},
		}...)
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("expected valid gzip output: %v", err)
		}
		decoded, _ := io.ReadAll(r)
		r.Close()
		if string(decoded) != "hi world" {
			t.Errorf("decompressed body = %q, want %q", string(decoded), "hi world")
		}
		if req.ContentLength != int64(len(body)) {
			t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
		}
	})
}


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
		if err := rewriteRespBody(context.Background(), nil); err != nil {
			t.Errorf("rewriteRespBody(context.Background(), nil) = %v, want nil", err)
		}
	})

	t.Run("no rewrites", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(context.Background(), resp)
		// Body unchanged
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "original" {
			t.Errorf("body = %q, want %q", string(got), "original")
		}
	})

	t.Run("zero content length", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: 0,
			Header:        http.Header{"Content-Type": {"text/plain"}},
			Body:          io.NopCloser(strings.NewReader("original")),
		}
		_ = rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
			Pattern:     regexp.MustCompile(".*"),
			Type:        "*",
			Replacement: []byte("replaced"),
		})
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "replaced" {
			t.Errorf("body = %q, want %q", string(got), "replaced")
		}
	})

	t.Run("with content encoding", func(t *testing.T) {
		original := []byte("original")
		compressed := compressTestData(original, "gzip")
		resp := &http.Response{
			Header:        http.Header{"Content-Encoding": {"gzip"}},
			ContentLength: int64(len(compressed)),
			Body:          io.NopCloser(bytes.NewReader(compressed)),
		}
		_ = rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
			Type:        "*",
			Pattern:     regexp.MustCompile(".*"),
			Replacement: []byte("replaced"),
		})
		got, _ := io.ReadAll(resp.Body)
		// Output is gzip-compressed, decompress to verify.
		r, err := gzip.NewReader(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("expected valid gzip output: %v", err)
		}
		decoded, _ := io.ReadAll(r)
		r.Close()
		if string(decoded) != "replaced" {
			t.Errorf("decompressed body = %q, want %q", string(decoded), "replaced")
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
		_ = rewriteRespBody(context.Background(), resp, makeRewrite("text/html", "replaced"))
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
		_ = rewriteRespBody(context.Background(), resp, makeRewrite("*", "world"))
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
		_ = rewriteRespBody(context.Background(), resp, makeRewrite("text/html", "replaced"))
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
		_ = rewriteRespBody(context.Background(), resp, makeRewrite("", "replaced"))
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
	frame.WriteByte(0x81)               // FIN + text
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

// =============================================================================
// resolveHTTPNode Tests
// =============================================================================

type configurableHop struct {
	node *chain.Node
}

func (h *configurableHop) Select(_ context.Context, _ ...hop.SelectOption) *chain.Node {
	return h.node
}

var _ hop.Hop = (*configurableHop)(nil)

func TestResolveHTTPNode_Bypass(t *testing.T) {
	ho := &HandleOptions{
		service:        "test-svc",
		bypass:         &mockBypass{contains: true},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}
	req, _ := http.NewRequest("GET", "http://example.com/path", nil)

	node, res, err := resolveHTTPNode(context.Background(), "example.com:80", req, ho)
	if err == nil {
		t.Fatal("expected bypass error, got nil")
	}
	if node != nil {
		t.Error("node should be nil on bypass")
	}
	if res == nil {
		t.Fatal("res should not be nil on bypass")
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusForbidden)
	}
}

func TestResolveHTTPNode_NoHop(t *testing.T) {
	ho := &HandleOptions{
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}
	req, _ := http.NewRequest("GET", "http://example.com/path", nil)

	node, res, err := resolveHTTPNode(context.Background(), "example.com:80", req, ho)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Error("res should be nil on success")
	}
	if node == nil {
		t.Fatal("node should not be nil")
	}
	if node.Addr != "example.com:80" {
		t.Errorf("node.Addr = %q, want %q", node.Addr, "example.com:80")
	}
}

func TestResolveHTTPNode_HopReturnsNil(t *testing.T) {
	ho := &HandleOptions{
		hop:            &configurableHop{node: nil},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}
	req, _ := http.NewRequest("GET", "http://example.com/path", nil)

	node, res, err := resolveHTTPNode(context.Background(), "example.com:80", req, ho)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "node not available" {
		t.Errorf("err = %q, want %q", err.Error(), "node not available")
	}
	if node != nil {
		t.Error("node should be nil on error")
	}
	if res == nil {
		t.Fatal("res should not be nil")
	}
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusBadGateway)
	}
}

func TestResolveHTTPNode_HopReturnsValidNode(t *testing.T) {
	expectedNode := &chain.Node{Name: "backend", Addr: "10.0.0.1:8080"}
	ho := &HandleOptions{
		hop:            &configurableHop{node: expectedNode},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}
	req, _ := http.NewRequest("GET", "http://example.com/path", nil)

	node, res, err := resolveHTTPNode(context.Background(), "example.com:80", req, ho)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Error("res should be nil on success")
	}
	if node != expectedNode {
		t.Errorf("node = %v, want %v", node, expectedNode)
	}
}

func TestResolveHTTPNode_HopReturnsNodeWithoutAddr(t *testing.T) {
	ho := &HandleOptions{
		hop:            &configurableHop{node: &chain.Node{Name: "backend"}},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}
	req, _ := http.NewRequest("GET", "http://example.com/path", nil)

	node, res, err := resolveHTTPNode(context.Background(), "example.com:80", req, ho)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Error("res should be nil on success")
	}
	if node == nil {
		t.Fatal("node should not be nil")
	}
	if node.Addr != "example.com:80" {
		t.Errorf("node.Addr = %q, want %q (host fallback)", node.Addr, "example.com:80")
	}
	if node.Name != "backend" {
		t.Errorf("node.Name = %q, want %q", node.Name, "backend")
	}
}

// =============================================================================
// resolveTLSNode Tests
// =============================================================================

func TestResolveTLSNode_NoHop(t *testing.T) {
	ho := &HandleOptions{
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}

	node, err := resolveTLSNode(context.Background(), "example.com", ho)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node == nil {
		t.Fatal("node should not be nil")
	}
	if node.Addr != "example.com" {
		t.Errorf("node.Addr = %q, want %q", node.Addr, "example.com")
	}
}

func TestResolveTLSNode_HopReturnsNil(t *testing.T) {
	ho := &HandleOptions{
		hop:            &configurableHop{node: nil},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}

	node, err := resolveTLSNode(context.Background(), "example.com", ho)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "node not available" {
		t.Errorf("err = %q, want %q", err.Error(), "node not available")
	}
	if node != nil {
		t.Error("node should be nil on error")
	}
}

func TestResolveTLSNode_HopReturnsValidNode(t *testing.T) {
	expectedNode := &chain.Node{Name: "backend", Addr: "10.0.0.1:443"}
	ho := &HandleOptions{
		hop:            &configurableHop{node: expectedNode},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}

	node, err := resolveTLSNode(context.Background(), "example.com", ho)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node != expectedNode {
		t.Errorf("node = %v, want %v", node, expectedNode)
	}
}

func TestResolveTLSNode_HopReturnsNodeWithoutAddr(t *testing.T) {
	ho := &HandleOptions{
		hop:            &configurableHop{node: &chain.Node{Name: "backend"}},
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}

	node, err := resolveTLSNode(context.Background(), "example.com", ho)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node == nil {
		t.Fatal("node should not be nil")
	}
	if node.Addr != "example.com" {
		t.Errorf("node.Addr = %q, want %q (host fallback)", node.Addr, "example.com")
	}
	if node.Name != "backend" {
		t.Errorf("node.Name = %q, want %q", node.Name, "backend")
	}
}

// =============================================================================
// handleUpgradeResponse Tests
// =============================================================================

func TestHandleUpgradeResponse_TypeMismatch(t *testing.T) {
	h := &Sniffer{}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"h2c"},
		},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	err := h.handleUpgradeResponse(context.Background(), serverConn, clientConn, req, res,
		&xrecorder.HandlerRecorderObject{}, xlogger.Nop())
	if err == nil {
		t.Fatal("expected type mismatch error, got nil")
	}
}

func TestHandleUpgradeResponse_NonWebsocket(t *testing.T) {
	h := &Sniffer{Websocket: false}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"h2c"},
		},
	}

	errCh := make(chan error, 1)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		errCh <- h.handleUpgradeResponse(context.Background(), serverConn, clientConn, req, res,
			&xrecorder.HandlerRecorderObject{}, xlogger.Nop())
	}()

	br := bufio.NewReader(clientConn)
	readResp, readErr := http.ReadResponse(br, req)
	if readErr != nil {
		t.Fatalf("reading upgrade response: %v", readErr)
	}
	if readResp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("status = %d, want %d", readResp.StatusCode, http.StatusSwitchingProtocols)
	}

	clientConn.Close()
	serverConn.Close()
	<-errCh
}

// =============================================================================
// rewriteRespBody Additional Tests
// =============================================================================

func TestRewriteRespBody_PatternReplacement(t *testing.T) {
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("<title>Old Title</title>")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:     regexp.MustCompile("Old"),
		Type:        "text/html",
		Replacement: []byte("New"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "<title>New Title</title>" {
		t.Errorf("body = %q, want %q", string(got), "<title>New Title</title>")
	}
	if resp.ContentLength != int64(len("<title>New Title</title>")) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len("<title>New Title</title>"))
	}
}

func TestRewriteRespBody_MultipleRewrites(t *testing.T) {
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("hello")),
	}
	err := rewriteRespBody(context.Background(), resp,
		chain.HTTPBodyRewriteSettings{
			Pattern:     regexp.MustCompile("h.*o"),
			Type:        "text/html",
			Replacement: []byte("first"),
		},
		chain.HTTPBodyRewriteSettings{
			Pattern:     regexp.MustCompile("first"),
			Type:        "text/html",
			Replacement: []byte("second"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "second" {
		t.Errorf("body = %q, want %q", string(got), "second")
	}
}

func TestRewriteRespBody_NilPattern(t *testing.T) {
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("original")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:     nil,
		Type:        "*",
		Replacement: []byte("replaced"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "original" {
		t.Errorf("body = %q, want %q (unchanged)", string(got), "original")
	}
}

func TestRewriteRespBody_EmptyContentTypeUsesDefault(t *testing.T) {
	resp := &http.Response{
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("original")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:     regexp.MustCompile(".*"),
		Type:        "",
		Replacement: []byte("rewritten"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "rewritten" {
		t.Errorf("body = %q, want %q", string(got), "rewritten")
	}
}

func TestRewriteRespBody_DefaultMaxChunkSize(t *testing.T) {
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader("original")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:     regexp.MustCompile("original"),
		Type:        "*",
		Replacement: []byte("rewritten"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "rewritten" {
		t.Errorf("body = %q, want %q (default 1MB maxChunkSize should buffer and rewrite)", string(got), "rewritten")
	}
	if resp.ContentLength != int64(len("rewritten")) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len("rewritten"))
	}
}

func TestRewriteRespBody_MaxChunkSize_Fits(t *testing.T) {
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader("original")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:      regexp.MustCompile(".*"),
		Type:         "*",
		Replacement:  []byte("rewritten"),
		MaxChunkSize: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "rewritten" {
		t.Errorf("body = %q, want %q", string(got), "rewritten")
	}
	if resp.ContentLength != int64(len("rewritten")) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len("rewritten"))
	}
	if resp.TransferEncoding != nil {
		t.Errorf("TransferEncoding = %v, want nil", resp.TransferEncoding)
	}
}

func TestRewriteRespBody_MaxChunkSize_Overflow(t *testing.T) {
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader("original")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:      regexp.MustCompile(".*"),
		Type:         "*",
		Replacement:  []byte("rewritten"),
		MaxChunkSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "original" {
		t.Errorf("body = %q, want %q (unchanged, overflow)", string(got), "original")
	}
	if resp.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1", resp.ContentLength)
	}
}

func TestRewriteRespBody_MaxChunkSize_Compressed_Fits(t *testing.T) {
	original := []byte("hello world")
	compressed := compressTestData(original, "gzip")
	resp := &http.Response{
		Header:        http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/plain"}},
		ContentLength: -1,
		Body:          io.NopCloser(bytes.NewReader(compressed)),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:      regexp.MustCompile("hello"),
		Type:         "*",
		Replacement:  []byte("hi"),
		MaxChunkSize: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Body should be decompressed → rewritten → recompressed.
	got, _ := io.ReadAll(resp.Body)
	gr, err := gzip.NewReader(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("expected valid gzip output: %v", err)
	}
	decoded, _ := io.ReadAll(gr)
	gr.Close()
	if string(decoded) != "hi world" {
		t.Errorf("decompressed body = %q, want %q", string(decoded), "hi world")
	}
	if resp.ContentLength != int64(len(got)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(got))
	}
	if resp.TransferEncoding != nil {
		t.Errorf("TransferEncoding = %v, want nil", resp.TransferEncoding)
	}
}

// =============================================================================
// Rewriter Plugin Tests
// =============================================================================

// mockRewriter is a simple rewriter.Rewriter for testing.
type mockRewriter struct {
	cb     func(b []byte) []byte
	called bool
}

func (m *mockRewriter) Rewrite(_ context.Context, b []byte, _ ...rewriter.RewriteOption) ([]byte, error) {
	m.called = true
	if m.cb != nil {
		return m.cb(b), nil
	}
	return b, nil
}

func TestRewriteRespBody_RewriterNilPattern(t *testing.T) {
	rw := &mockRewriter{}
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("hello")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Type:     "*",
		Rewriter: rw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rw.called {
		t.Error("rewriter was not called")
	}
}

func TestRewriteRespBody_RewriterMatchPass(t *testing.T) {
	rw := &mockRewriter{
		cb: func(b []byte) []byte {
			return []byte("rewritten")
		},
	}
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("hello world")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Type:     "*",
		Pattern:  regexp.MustCompile("hello"),
		Rewriter: rw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rw.called {
		t.Fatal("rewriter was not called")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "rewritten" {
		t.Errorf("body = %q, want %q", string(body), "rewritten")
	}
	if resp.ContentLength != int64(len("rewritten")) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len("rewritten"))
	}
}

func TestRewriteRespBody_RewriterMatchSkip(t *testing.T) {
	rw := &mockRewriter{}
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/html"}},
		ContentLength: 100,
		Body:          io.NopCloser(strings.NewReader("hello world")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Type:     "*",
		Pattern:  regexp.MustCompile("xyz"),
		Rewriter: rw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rw.called {
		t.Fatal("rewriter should not have been called: body did not match pattern")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello world" {
		t.Errorf("body = %q, want %q (unchanged)", string(body), "hello world")
	}
}

func TestRewriteRespBody_RewriterContentTypeFilter(t *testing.T) {
	rw := &mockRewriter{
		cb: func(b []byte) []byte { return []byte("rewritten") },
	}

	t.Run("type matches calls rewriter", func(t *testing.T) {
		rw.called = false
		resp := &http.Response{
			Header:        http.Header{"Content-Type": {"application/json"}},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader(`{"key":"value"}`)),
		}
		_ = rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
			Type:     "application/json",
			Rewriter: rw,
		})
		if !rw.called {
			t.Error("rewriter should have been called")
		}
	})

	t.Run("type mismatch skips rewriter", func(t *testing.T) {
		rw.called = false
		resp := &http.Response{
			Header:        http.Header{"Content-Type": {"text/plain"}},
			ContentLength: 100,
			Body:          io.NopCloser(strings.NewReader("hello")),
		}
		_ = rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
			Type:     "application/json",
			Rewriter: rw,
		})
		if rw.called {
			t.Error("rewriter should not have been called: content type mismatch")
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "hello" {
			t.Errorf("body = %q, want %q (unchanged)", string(body), "hello")
		}
	})
}

func TestRewriteReqBody_Rewriter(t *testing.T) {
	rw := &mockRewriter{
		cb: func(b []byte) []byte {
			return []byte("rewritten")
		},
	}

	t.Run("nil pattern calls rewriter", func(t *testing.T) {
		rw.called = false
		req := &http.Request{
			Body:          io.NopCloser(strings.NewReader("hello")),
			ContentLength: 5,
			Header:        http.Header{"Content-Type": {"text/plain"}},
		}
		_ = rewriteReqBody(context.Background(), req, chain.HTTPBodyRewriteSettings{
			Type:     "*",
			Rewriter: rw,
		})
		if !rw.called {
			t.Fatal("rewriter was not called")
		}
		body, _ := io.ReadAll(req.Body)
		if string(body) != "rewritten" {
			t.Errorf("body = %q, want %q", string(body), "rewritten")
		}
	})

	t.Run("match passes through to rewriter", func(t *testing.T) {
		rw.called = false
		req := &http.Request{
			Body:          io.NopCloser(strings.NewReader("hello world")),
			ContentLength: 11,
			Header:        http.Header{"Content-Type": {"text/html"}},
		}
		_ = rewriteReqBody(context.Background(), req, chain.HTTPBodyRewriteSettings{
			Type:     "text/html",
			Pattern:  regexp.MustCompile("hello"),
			Rewriter: rw,
		})
		if !rw.called {
			t.Fatal("rewriter was not called")
		}
		body, _ := io.ReadAll(req.Body)
		if string(body) != "rewritten" {
			t.Errorf("body = %q, want %q", string(body), "rewritten")
		}
	})

	t.Run("non-match skips rewriter", func(t *testing.T) {
		rw.called = false
		req := &http.Request{
			Body:          io.NopCloser(strings.NewReader("hello world")),
			ContentLength: 11,
			Header:        http.Header{"Content-Type": {"text/html"}},
		}
		_ = rewriteReqBody(context.Background(), req, chain.HTTPBodyRewriteSettings{
			Type:     "text/html",
			Pattern:  regexp.MustCompile("xyz"),
			Rewriter: rw,
		})
		if rw.called {
			t.Fatal("rewriter should not have been called: body did not match pattern")
		}
		body, _ := io.ReadAll(req.Body)
		if string(body) != "hello world" {
			t.Errorf("body = %q, want %q (unchanged)", string(body), "hello world")
		}
	})
}

func TestCopyWebsocketFrame_EmptyPayload(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
	}

	var frame bytes.Buffer
	frame.WriteByte(0x81) // FIN + text
	frame.WriteByte(0x00) // MASK=0, len=0

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "server", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if ro.Websocket.Length != 0 {
		t.Errorf("payload length = %d, want 0", ro.Websocket.Length)
	}
	if len(ro.Websocket.Payload) != 0 {
		t.Errorf("payload = %q, want empty", ro.Websocket.Payload)
	}
}

func TestCopyWebsocketFrame_ServerWithoutBodyRecording(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	payload := []byte("data")
	var frame bytes.Buffer
	frame.WriteByte(0x82)               // FIN + binary
	frame.WriteByte(byte(len(payload))) // MASK=0, len=4
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
	if ro.Websocket.Payload != nil {
		t.Error("payload should be nil when body recording is disabled")
	}
	if ro.Websocket.OpCode != 2 {
		t.Errorf("opcode = %d, want 2 (binary)", ro.Websocket.OpCode)
	}
	if ro.OutputBytes == 0 {
		t.Error("OutputBytes should be non-zero for server direction")
	}
	if ro.InputBytes != 0 {
		t.Error("InputBytes should be zero for server direction")
	}
}

func TestCopyWebsocketFrame_MaskedFrame(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	payload := []byte("secret")
	mask := []byte{0x12, 0x34, 0x56, 0x78}
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ mask[i%4]
	}

	var frame bytes.Buffer
	frame.WriteByte(0x81)                      // FIN + text
	frame.WriteByte(0x80 | byte(len(payload))) // MASK=1, len
	frame.Write(mask)
	frame.Write(maskedPayload)

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "client", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if !ro.Websocket.Masked {
		t.Error("client frame should be masked")
	}
	written := w.Bytes()
	if len(written) < 2+len(payload) {
		t.Fatalf("written frame too short: %d bytes", len(written))
	}
	if written[0] != 0x81 {
		t.Errorf("first byte = 0x%02x, want 0x81", written[0])
	}
	if written[1]&0x80 != 0x80 {
		t.Error("mask bit should be preserved")
	}
}

// =============================================================================
// serveH2 unit test (client preface)
// =============================================================================

func TestServeH2_InvalidPreface(t *testing.T) {
	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ho := &HandleOptions{
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// net.Pipe is synchronous: Write blocks until the other side Reads.
	// Write exactly 6 bytes (size of "SM\r\n\r\n" preface) then return.
	go func() {
		clientConn.Write([]byte("XXXXXX"))
	}()

	err := h.serveH2(context.Background(), serverConn, ho)
	if err == nil {
		t.Error("expected error from invalid h2 preface, got nil")
	}
}

// =============================================================================
// SSE (Server-Sent Events) Tests
// =============================================================================


func TestRewriteRespBody_SSE_ContentType(t *testing.T) {
	// rewriteRespBody now rewrites SSE per-event via the universal wrapper.
	resp := &http.Response{
		Header:        http.Header{"Content-Type": {"text/event-stream"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader("data: hello\n\n")),
	}
	err := rewriteRespBody(context.Background(), resp, chain.HTTPBodyRewriteSettings{
		Pattern:     regexp.MustCompile("data: hello"),
		Type:        "*",
		Replacement: []byte("data: world"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "data: world\n\n" {
		t.Errorf("body = %q, want %q", string(got), "data: world\n\n")
	}
}

func TestNewRewriteBody(t *testing.T) {
	makeRewrite := func(rewriteType, match, replace string) chain.HTTPBodyRewriteSettings {
		return chain.HTTPBodyRewriteSettings{
			Pattern:     regexp.MustCompile(match),
			Type:        rewriteType,
			Replacement: []byte(replace),
		}
	}

	t.Run("regex replacement streaming", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: hello\n\n"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "hello", "world"),
		}, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "data: world\n\n" {
			t.Errorf("body = %q, want %q", string(got), "data: world\n\n")
		}
	})

	t.Run("multiple events streaming", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: a\n\ndata: b\n\ndata: c\n\n"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "data: [ab]$", "data: x"),
		}, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		expected := "data: x\n\ndata: x\n\ndata: c\n\n"
		if string(got) != expected {
			t.Errorf("body = %q, want %q", string(got), expected)
		}
	})

	t.Run("multiple rewrite rules streaming", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: hello\n\n"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "hello", "world"),
			makeRewrite("*", "world", "there"),
		}, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "data: there\n\n" {
			t.Errorf("body = %q, want %q", string(got), "data: there\n\n")
		}
	})

	t.Run("content type filter streaming", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: hello\n\n"))
		// text/html type rule — won't match text/event-stream.
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			{Type: "text/html", Pattern: regexp.MustCompile("hello"), Replacement: []byte("world")},
		}, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "data: hello\n\n" {
			t.Errorf("body = %q, want %q (unchanged)", string(got), "data: hello\n\n")
		}
	})

	t.Run("no rewrites returns nil", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: hello\n\n"))
		body, err := newRewriteBody(context.Background(), src, nil, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			t.Error("expected nil for no rewrites")
		}
	})

	t.Run("content encoding returns nil", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: hello\n\n"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "hello", "world"),
		}, "text/event-stream", "gzip", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			t.Error("expected nil for Content-Encoding")
		}
	})

	t.Run("plugin rewriter streaming", func(t *testing.T) {
		rw := &mockRewriter{
			cb: func(b []byte) []byte { return []byte("data: rewritten") },
		}
		src := io.NopCloser(strings.NewReader("data: original\n\n"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			{Type: "*", Rewriter: rw},
		}, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "data: rewritten\n\ndata: rewritten\n\n" {
			t.Errorf("body = %q, want %q", string(got), "data: rewritten\n\ndata: rewritten\n\n")
		}
	})

	t.Run("incomplete final event flushed", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("data: hello"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "hello", "world"),
		}, "text/event-stream", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "data: world\n\n" {
			t.Errorf("body = %q, want %q", string(got), "data: world\n\n")
		}
	})

	t.Run("non-streaming body rewritten", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("hello world"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "hello", "hi"),
		}, "text/plain", "", 11, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body")
		}

		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "hi world" {
			t.Errorf("body = %q, want %q", string(got), "hi world")
		}
		if body.contentLength != int64(len("hi world")) {
			t.Errorf("contentLength = %d, want %d", body.contentLength, len("hi world"))
		}
	})

	t.Run("chunked non-streaming uses default maxChunkSize", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("hello world"))
		body, err := newRewriteBody(context.Background(), src, []chain.HTTPBodyRewriteSettings{
			makeRewrite("*", "hello", "hi"),
		}, "text/plain", "", -1, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			t.Fatal("expected non-nil body (default 1MB maxChunkSize)")
		}
		got, _ := io.ReadAll(body)
		body.Close()
		if string(got) != "hi world" {
			t.Errorf("body = %q, want %q", string(got), "hi world")
		}
	})
}

func TestRewriteRespBody_CompressedEncodings(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
	}{
		{"gzip", "gzip"},
		{"deflate", "deflate"},
		{"br", "br"},
		{"zstd", "zstd"},
	}

	input := []byte("hello world")
	rewrites := []chain.HTTPBodyRewriteSettings{
		{
			Type:        "*",
			Pattern:     regexp.MustCompile("hello"),
			Replacement: []byte("hi"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := compressTestData(input, tt.encoding)
			resp := &http.Response{
				Header:        http.Header{"Content-Encoding": {tt.encoding}, "Content-Type": {"text/plain"}},
				ContentLength: int64(len(compressed)),
				Body:          io.NopCloser(bytes.NewReader(compressed)),
			}
			if err := rewriteRespBody(context.Background(), resp, rewrites...); err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Output is recompressed; decompress to verify rewrite.
			decoded, err := decompressBody(got, tt.encoding)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if string(decoded) != "hi world" {
				t.Errorf("decompressed body = %q, want %q", string(decoded), "hi world")
			}
		})
	}
}
