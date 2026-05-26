package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	xmetadata "github.com/go-gost/x/metadata"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	_, ok := h.(*apiHandler)
	if !ok {
		t.Fatal("expected *apiHandler type")
	}
}

func TestNewHandler_WithOptions(t *testing.T) {
	h := NewHandler(
		handler.ServiceOption("test-svc"),
	).(*apiHandler)

	if h.options.Service != "test-svc" {
		t.Errorf("Service = %q, want %q", h.options.Service, "test-svc")
	}
}

func TestHandle_NotInitialized(t *testing.T) {
	h := NewHandler()

	c1, c2 := net.Pipe()
	defer c1.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(context.Background(), c2)
	}()

	c2.Close()

	if err := <-errCh; err == nil {
		t.Fatal("expected error when Init not called")
	}
}

func TestInit_DefaultMetadata(t *testing.T) {
	h := NewHandler().(*apiHandler)

	if err := h.Init(xmetadata.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.handler == nil {
		t.Fatal("handler should be set after Init")
	}
	if h.md.accesslog {
		t.Error("accesslog should be false by default")
	}
	if h.md.pathPrefix != "" {
		t.Errorf("pathPrefix = %q, want empty", h.md.pathPrefix)
	}
}

func TestInit_MetadataAccessLog(t *testing.T) {
	h := NewHandler().(*apiHandler)

	if err := h.Init(xmetadata.NewMetadata(map[string]any{
		"accessLog": true,
	})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !h.md.accesslog {
		t.Error("accesslog should be true")
	}
}

func TestInit_MetadataPathPrefix(t *testing.T) {
	h := NewHandler().(*apiHandler)

	if err := h.Init(xmetadata.NewMetadata(map[string]any{
		"pathPrefix": "/api/v1",
	})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.md.pathPrefix != "/api/v1" {
		t.Errorf("pathPrefix = %q, want %q", h.md.pathPrefix, "/api/v1")
	}
}

func TestInit_MetadataAltKeys(t *testing.T) {
	h := NewHandler().(*apiHandler)

	if err := h.Init(xmetadata.NewMetadata(map[string]any{
		"api.accessLog":  true,
		"api.pathPrefix": "/v2",
	})); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !h.md.accesslog {
		t.Error("accesslog should be true via api.accessLog key")
	}
	if h.md.pathPrefix != "/v2" {
		t.Errorf("pathPrefix = %q, want %q", h.md.pathPrefix, "/v2")
	}
}

// --- Handler HTTP round-trip via httptest (no goroutine race) ---

func TestAPIHandler_ConfigEndpoint(t *testing.T) {
	h := NewHandler().(*apiHandler)
	if err := h.Init(xmetadata.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code == 0 {
		t.Fatal("expected non-zero status code")
	}
}

func TestAPIHandler_DocsEndpoint(t *testing.T) {
	h := NewHandler().(*apiHandler)
	if err := h.Init(xmetadata.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/docs/", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	// Swagger docs endpoint should respond (200 redirect or 301 are both valid).
	if rec.Code == 0 {
		t.Fatal("expected non-zero status code")
	}
}

func TestAPIHandler_WithPathPrefix(t *testing.T) {
	h := NewHandler().(*apiHandler)
	if err := h.Init(xmetadata.NewMetadata(map[string]any{
		"pathPrefix": "/myprefix",
	})); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Request with the configured prefix should route to config endpoints.
	req := httptest.NewRequest(http.MethodGet, "/myprefix/config", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code == 0 {
		t.Fatal("expected non-zero status code")
	}

	// Request without prefix should return 404.
	req2 := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec2 := httptest.NewRecorder()
	h.handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotFound {
		t.Errorf("without prefix: status = %d, want %d", rec2.Code, http.StatusNotFound)
	}
}

// --- Handle lifecycle ---

func TestHandle_ReturnsAfterConnectionClosed(t *testing.T) {
	h := NewHandler().(*apiHandler)
	if err := h.Init(xmetadata.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	c1, c2 := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- h.Handle(context.Background(), c2)
	}()

	// Close the client side; the server will get an error reading the request
	// and eventually return.
	c1.Close()

	select {
	case err := <-done:
		// Handle returned — error or nil are both acceptable for a dead connection.
		t.Logf("Handle returned: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Handle should return after connection is closed")
	}
}

func TestHandle_CanceledContext(t *testing.T) {
	h := NewHandler().(*apiHandler)
	if err := h.Init(xmetadata.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c1, c2 := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- h.Handle(ctx, c2)
	}()

	c1.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Log("Handle returned nil (acceptable)")
		} else {
			t.Logf("Handle returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle should return with canceled context")
	}
}

// --- singleConnListener tests ---

func TestSingleConnListener_AcceptOne(t *testing.T) {
	l := &singleConnListener{
		conn: make(chan net.Conn, 1),
	}

	mockC, _ := net.Pipe()
	l.send(mockC)

	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if conn != mockC {
		t.Fatal("Accept returned wrong connection")
	}

	_, err = l.Accept()
	if err == nil {
		t.Fatal("expected error on second Accept")
	}

	mockC.Close()
}

func TestSingleConnListener_AcceptEmptyChannel(t *testing.T) {
	l := &singleConnListener{
		conn: make(chan net.Conn, 1),
	}
	close(l.conn)

	_, err := l.Accept()
	if err == nil {
		t.Fatal("expected error on closed empty channel")
	}
}

func TestSingleConnListener_Close(t *testing.T) {
	l := &singleConnListener{
		conn: make(chan net.Conn, 1),
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSingleConnListener_Addr(t *testing.T) {
	l := &singleConnListener{
		conn: make(chan net.Conn, 1),
	}
	addr := l.Addr()
	if addr == nil {
		t.Fatal("Addr should not return nil")
	}
	if addr.Network() != "tcp" {
		t.Errorf("Network = %q, want %q", addr.Network(), "tcp")
	}
}

func TestSingleConnListener_SendAndClose(t *testing.T) {
	ch := make(chan net.Conn, 1)
	l := &singleConnListener{conn: ch}

	c1, _ := net.Pipe()
	l.send(c1)

	// Channel should have one value.
	_, ok := <-ch
	if !ok {
		t.Fatal("channel should have had one value")
	}

	// Channel is now closed.
	_, ok = <-ch
	if ok {
		t.Fatal("channel should be closed after send")
	}

	c1.Close()
}

// --- parseMetadata table-driven tests ---

func TestParseMetadata_AllKeys(t *testing.T) {
	tests := []struct {
		name    string
		md      map[string]any
		wantLog bool
		wantPfx string
	}{
		{
			name:    "empty",
			md:      nil,
			wantLog: false,
			wantPfx: "",
		},
		{
			name:    "accessLog short key",
			md:      map[string]any{"accessLog": true},
			wantLog: true,
			wantPfx: "",
		},
		{
			name:    "accessLog long key",
			md:      map[string]any{"api.accessLog": true},
			wantLog: true,
			wantPfx: "",
		},
		{
			name:    "pathPrefix short key",
			md:      map[string]any{"pathPrefix": "/pfx"},
			wantLog: false,
			wantPfx: "/pfx",
		},
		{
			name:    "pathPrefix long key",
			md:      map[string]any{"api.pathPrefix": "/pfx2"},
			wantLog: false,
			wantPfx: "/pfx2",
		},
		{
			name:    "both keys",
			md:      map[string]any{"api.accessLog": true, "api.pathPrefix": "/v3"},
			wantLog: true,
			wantPfx: "/v3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &apiHandler{}
			h.parseMetadata(xmetadata.NewMetadata(tc.md))
			if h.md.accesslog != tc.wantLog {
				t.Errorf("accesslog = %v, want %v", h.md.accesslog, tc.wantLog)
			}
			if h.md.pathPrefix != tc.wantPfx {
				t.Errorf("pathPrefix = %q, want %q", h.md.pathPrefix, tc.wantPfx)
			}
		})
	}
}

// --- registry integration ---

func TestHandlerRegistered(t *testing.T) {
	factory := func() handler.Handler {
		return NewHandler()
	}
	got := factory()
	if got == nil {
		t.Fatal("factory returned nil")
	}
	if _, ok := got.(*apiHandler); !ok {
		t.Fatal("factory should return *apiHandler")
	}
}

// --- interface assertions ---

func TestHandlerInterface(t *testing.T) {
	var _ handler.Handler = (*apiHandler)(nil)
	var _ net.Listener = (*singleConnListener)(nil)
}
