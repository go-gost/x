package http

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	cmdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	xmetadata "github.com/go-gost/x/metadata"
)

func testMD(m map[string]any) cmdata.Metadata {
	return xmetadata.NewMetadata(m)
}

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	httpH, ok := h.(*httpHandler)
	if !ok {
		t.Fatal("NewHandler did not return *httpHandler")
	}
	if httpH.options.Logger != nil {
		t.Error("expected nil logger")
	}
}

func TestNewHandler_WithOptions(t *testing.T) {
	log := &testLogger{}
	h := NewHandler(
		handler.LoggerOption(log),
		handler.ServiceOption("test-service"),
	)
	httpH := h.(*httpHandler)
	if httpH.options.Logger == nil {
		t.Error("expected logger to be set")
	}
	if httpH.options.Service != "test-service" {
		t.Errorf("got service %q, want %q", httpH.options.Service, "test-service")
	}
}

func TestInit(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
	).(*httpHandler)

	err := h.Init(testMD(map[string]any{}))
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if h.transport == nil {
		t.Error("expected transport to be initialized")
	}
	if h.md.proxyAgent == "" {
		t.Error("expected default proxy agent")
	}
	if h.md.readTimeout == 0 {
		t.Error("expected default read timeout")
	}
}

func TestInit_WithObserver(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
		handler.ObserverOption(&testObserver{}),
	).(*httpHandler)

	err := h.Init(testMD(map[string]any{}))
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if h.stats == nil {
		t.Error("expected stats to be initialized when observer is set")
	}
}

func TestInit_WithLimiter(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
		handler.TrafficLimiterOption(&testTrafficLimiter{}),
	).(*httpHandler)

	err := h.Init(testMD(map[string]any{}))
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if h.limiter == nil {
		t.Error("expected limiter to be initialized")
	}
}

func TestInit_WithRecorder(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
	).(*httpHandler)

	err := h.Init(testMD(map[string]any{}))
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	// recorder is nil since no matching recorder was passed
	if h.recorder.Record != "" {
		t.Log("recorder found even without explicit match")
	}
}

func TestClose(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
	).(*httpHandler)

	err := h.Init(testMD(map[string]any{}))
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if h.cancel == nil {
		t.Fatal("expected cancel function")
	}

	err = h.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestClose_NoInit(t *testing.T) {
	h := NewHandler().(*httpHandler)
	err := h.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestHandle_PRIMethod(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
	).(*httpHandler)
	if err := h.Init(testMD(map[string]any{})); err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Write an HTTP/2 connection preface which parses as a PRI request
		client.Write([]byte("PRI * HTTP/2.0\r\nHost: example.com\r\n\r\n"))
		// Drain any response so Pipe doesn't block
		io.ReadAll(client)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := h.Handle(ctx, server)
	if err != nil {
		t.Logf("Handle returned: %v", err)
	}
}

func TestHandle_InvalidHost(t *testing.T) {
	h := NewHandler(
		handler.LoggerOption(&testLogger{}),
	).(*httpHandler)
	if err := h.Init(testMD(map[string]any{})); err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Invalid host that fails DNS name and IP parsing
		client.Write([]byte("GET / HTTP/1.1\r\nHost: !!!invalid!!!\r\n\r\n"))
		// Drain any response so Pipe doesn't block
		io.ReadAll(client)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := h.Handle(ctx, server)
	if err != nil {
		t.Logf("Handle returned: %v", err)
	}
}

func TestSetupTrafficLimiter_NoObserver(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger:  &testLogger{},
			Service: "test",
		},
	}

	client, _ := net.Pipe()
	defer client.Close()

	result, done := h.setupTrafficLimiter(client, "test-client", "tcp", "example.com:80")
	_ = done
	if result == nil {
		t.Error("expected non-nil connection")
	}
}

// testObserver implements observer.Observer for testing.
type testObserver struct{}

func (o *testObserver) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	return nil
}
