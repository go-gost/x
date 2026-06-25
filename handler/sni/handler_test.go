package sni

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/recorder"
	xmd "github.com/go-gost/x/metadata"
	xrecorder "github.com/go-gost/x/recorder"
)

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler(func(o *handler.Options) {
		o.Service = "test-svc"
	})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	sh, ok := h.(*sniHandler)
	if !ok {
		t.Fatal("expected *sniHandler")
	}
	if sh.options.Service != "test-svc" {
		t.Errorf("expected Service 'test-svc', got %s", sh.options.Service)
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func TestInit_Defaults(t *testing.T) {
	h := newTestHandler()
	err := h.Init(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.readTimeout <= 0 {
		t.Error("expected positive default readTimeout")
	}
	if h.sniffer == nil {
		t.Error("expected sniffer to be initialised")
	}
}

func TestInit_SelectsRecorder(t *testing.T) {
	h := newTestHandler(withRecorder(recorder.RecorderObject{
		Record:   xrecorder.RecorderServiceHandler,
		Recorder: &mockRecorder{},
	}))
	err := h.Init(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.recorder.Recorder == nil {
		t.Error("expected recorder to be set")
	}
}

func TestInit_CertPool(t *testing.T) {
	cert, key := generateTestCertKey(t)
	h := newTestHandler()
	h.md.certificate = cert
	h.md.privateKey = key
	err := h.Init(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.certPool == nil {
		t.Error("expected certPool to be created")
	}
}

func TestInit_ParseMetadataError(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": "/nonexistent/cert.pem",
		"mitm.keyFile":  "/nonexistent/key.pem",
	})
	err := h.Init(md)
	if err == nil {
		t.Fatal("expected error from Init with bad cert files")
	}
}

// ---------------------------------------------------------------------------
// Handle — error paths
// ---------------------------------------------------------------------------

func TestHandle_NoRouter(t *testing.T) {
	h := newTestHandler(withRouter(nil))
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error when router is nil")
	}
	if !errors.Is(err, errRouterNotAvailable) {
		t.Errorf("expected errRouterNotAvailable, got %v", err)
	}
}

func TestHandle_RateLimited(t *testing.T) {
	h := newInitdHandler(withRateLimiter(&stubRateLimiter{
		limiterFn: func(key string) rate.Limiter {
			return &stubLimiter{allowFn: func(n int) bool { return false }}
		},
	}))
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
}

// ---------------------------------------------------------------------------
// Handle — sniffing (protocol detection)
// ---------------------------------------------------------------------------

func TestHandle_SniffError(t *testing.T) {
	// An empty connection causes sniffing.Sniff to return an error because
	// there are no bytes to peek. The handler should log the error and fall
	// through to the unrecognised path (silent drop).
	h := newInitdHandler()
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("expected nil error for unrecognised traffic, got %v", err)
	}
}

func TestHandle_UnrecognizedProto(t *testing.T) {
	h := newInitdHandler()
	// Non-HTTP/non-TLS bytes won't match any sniffer protocol.
	conn := newStringConn([]byte("ssh-2.0-OpenSSH"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("expected nil error for unrecognised traffic, got %v", err)
	}
}

func TestHandle_HTTP(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		n, err := client.Read(buf)
		if err == nil && n > 0 {
			client.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	conn := newStringConn([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Logf("sniffed HTTP returned: %v", err)
	}
}

func TestHandle_TLS(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	conn := newStringConn([]byte{
		0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x03, 0x01,
	})

	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Log("sniffed TLS ClientHello without error")
	}
}

func TestHandle_RecorderError(t *testing.T) {
	// The deferred recorder error should not affect the return value.
	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, nil
		},
	}))
	h.recorder = recorder.RecorderObject{Recorder: &errorRecorder{}}
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("expected nil from unrecognised traffic, got %v", err)
	}
}

func TestHandle_WithReadTimeout(t *testing.T) {
	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
	}))
	h.md.readTimeout = 0 // zero disables the deadline
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	conn := newStringConn([]byte("ssh"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestHandle_ConnClosed(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !conn.closed {
		t.Error("expected connection to be closed after Handle returns")
	}
}
