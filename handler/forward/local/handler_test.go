package local

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/recorder"
	xmd "github.com/go-gost/x/metadata"
	xrecorder "github.com/go-gost/x/recorder"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(func(o *handler.Options) {
		o.Service = "test-svc"
	})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	fh, ok := h.(*forwardHandler)
	if !ok {
		t.Fatal("expected *forwardHandler")
	}
	if fh.options.Service != "test-svc" {
		t.Errorf("expected Service 'test-svc', got %s", fh.options.Service)
	}
}

func TestForward(t *testing.T) {
	h := newTestHandler()
	mh := &mockHop{}
	h.Forward(mh)
	if h.getHop() != mh {
		t.Error("expected hop to be set")
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

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
// Handle integration
// ---------------------------------------------------------------------------

func TestHandle_NoRouter(t *testing.T) {
	h := newTestHandler(func(o *handler.Options) {
		o.Router = nil
	})
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

func TestHandle_BasicForward(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 64)
		for {
			_, err := client.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1:80", Name: "target"}
		},
	})
	conn := newStringConn([]byte("hello"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandle_RecorderError(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.recorder = recorder.RecorderObject{Recorder: &errorRecorder{}}
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	})
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Handle — sniffing integration
// ---------------------------------------------------------------------------

func TestHandle_SniffingEnabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := client.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.md.sniffing = true
	h.md.sniffingTimeout = 5 * time.Second
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1:80", Name: "target"}
		},
	})
	conn := newStringConn([]byte("hello world"))
	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandle_SniffError(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.md.sniffing = true
	h.md.sniffingTimeout = 5 * time.Second
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	})
	conn := newStringConn(nil)

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandle_SniffHTTP(t *testing.T) {
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

	h := newTestHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.md.sniffing = true
	h.md.sniffingTimeout = 5 * time.Second
	h.recorder = recorder.RecorderObject{Recorder: &mockRecorder{}}
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	})
	conn := newStringConn([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))

	err := h.Handle(context.Background(), conn)
	if err != nil {
		t.Logf("sniffed HTTP path returned: %v", err)
	}
}
