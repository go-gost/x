package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	stats_util "github.com/go-gost/x/internal/util/stats"
	xrecorder "github.com/go-gost/x/recorder"
)


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

func TestHandleRequest_Bypass(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
			Bypass: &testBypass{contains: true},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15
	h.auth = &Authenticator{}

	conn := newStringConn("")
	req, _ := http.NewRequest("GET", "http://example.com:80/path", nil)

	err := h.handleRequest(context.Background(), conn, req, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err == nil {
		t.Error("expected bypass error")
	}
}

func TestHandleRequest_UDP_Disabled(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15
	h.auth = &Authenticator{}

	conn := newStringConn("")
	req, _ := http.NewRequest("GET", "http://example.com:80/path", nil)
	req.Header.Set("X-Gost-Protocol", "udp")

	err := h.handleRequest(context.Background(), conn, req, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	// UDP disabled → 403 Forbidden written
	if err != nil {
		t.Logf("handleRequest UDP disabled: %v", err)
	}
}

func TestHandleRequest_CONNECT_NonConnectMethod_NoScheme(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15
	h.auth = &Authenticator{}

	conn := newStringConn("")
	req, _ := http.NewRequest("PRI", "*", nil)

	err := h.handleRequest(context.Background(), conn, req, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err != nil {
		t.Logf("handleRequest PRI: %v", err)
	}
}

func TestHandleRequest_ProbeResistanceAuth(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15
	h.auth = &Authenticator{
		Auther: &stubAuther{accept: false},
		PR:     &probeResistance{Type: "code", Value: "404"},
	}

	conn := newStringConn("")
	req, _ := http.NewRequest("GET", "http://example.com:80/path", nil)

	err := h.handleRequest(context.Background(), conn, req, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err == nil {
		t.Error("expected auth failure")
	}
}

func TestObserveStats_NilObserver(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.observeStats(context.Background())
}

func TestObserveStats_SendsEvents(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger:   &testLogger{},
			Service:  "test",
			Observer: &testObserver{},
		},
	}
	h.md.observerPeriod = 50 * time.Millisecond
	h.stats = stats_util.NewHandlerStats("test", false)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		h.observeStats(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("observeStats did not exit after context cancellation")
	}
}

func TestHandleRequest_Bypass_Test(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
			Bypass: &testBypass{contains: true},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15
	h.auth = &Authenticator{}

	conn := newStringConn("")
	req, _ := http.NewRequest("GET", "http://example.com:80/path", nil)

	err := h.handleRequest(context.Background(), conn, req, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err == nil {
		t.Error("expected bypass error")
	}
}

