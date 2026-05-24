package observer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/x/internal/plugin"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/go-gost/x/service"
)

func TestNewHTTPPlugin(t *testing.T) {
	p := NewHTTPPlugin("test", "localhost:8080")
	if p == nil {
		t.Fatal("NewHTTPPlugin should not return nil")
	}
	hp, ok := p.(*httpPlugin)
	if !ok {
		t.Fatalf("NewHTTPPlugin returned %T, want *httpPlugin", p)
	}
	if hp.url != "http://localhost:8080" {
		t.Errorf("url = %s, want http://localhost:8080", hp.url)
	}
	if hp.client == nil {
		t.Error("client should not be nil")
	}
}

func TestNewHTTPPlugin_NoScheme(t *testing.T) {
	p := NewHTTPPlugin("test", "example.com:9999")
	hp := p.(*httpPlugin)
	if !strings.HasPrefix(hp.url, "http://") {
		t.Errorf("expected http:// prefix, got %s", hp.url)
	}
}

func TestNewHTTPPlugin_KeepsHTTPSScheme(t *testing.T) {
	p := NewHTTPPlugin("test", "https://example.com/api")
	hp := p.(*httpPlugin)
	if !strings.HasPrefix(hp.url, "https://") {
		t.Errorf("expected https:// prefix, got %s", hp.url)
	}
}

func TestHTTPPlugin_Observe_StatusEvent(t *testing.T) {
	var receivedBody json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{
			Kind:    "service",
			Service: "test-svc",
			State:   "running",
			Msg:     "started",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the event was sent correctly
	var req observeRequest
	if err := json.Unmarshal(receivedBody, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(req.Events))
	}
	if req.Events[0].Kind != "service" {
		t.Errorf("event kind = %s, want service", req.Events[0].Kind)
	}
	if req.Events[0].Service != "test-svc" {
		t.Errorf("event service = %s, want test-svc", req.Events[0].Service)
	}
	if req.Events[0].Status == nil {
		t.Fatal("status event should have Status field")
	}
	if req.Events[0].Status.State != "running" {
		t.Errorf("state = %s, want running", req.Events[0].Status.State)
	}
}

func TestHTTPPlugin_Observe_StatsEvent(t *testing.T) {
	var receivedBody json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{
			Kind:         "traffic",
			Service:      "svc",
			Client:       "c1",
			TotalConns:   100,
			CurrentConns: 5,
			InputBytes:   4096,
			OutputBytes:  8192,
			TotalErrs:    2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var req observeRequest
	if err := json.Unmarshal(receivedBody, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(req.Events))
	}
	if req.Events[0].Stats == nil {
		t.Fatal("stats event should have Stats field")
	}
	if req.Events[0].Stats.TotalConns != 100 {
		t.Errorf("totalConns = %d, want 100", req.Events[0].Stats.TotalConns)
	}
	if req.Events[0].Stats.CurrentConns != 5 {
		t.Errorf("currentConns = %d, want 5", req.Events[0].Stats.CurrentConns)
	}
	if req.Events[0].Stats.InputBytes != 4096 {
		t.Errorf("inputBytes = %d, want 4096", req.Events[0].Stats.InputBytes)
	}
	if req.Events[0].Stats.OutputBytes != 8192 {
		t.Errorf("outputBytes = %d, want 8192", req.Events[0].Stats.OutputBytes)
	}
	if req.Events[0].Stats.TotalErrs != 2 {
		t.Errorf("totalErrs = %d, want 2", req.Events[0].Stats.TotalErrs)
	}
	if req.Events[0].Client != "c1" {
		t.Errorf("client = %s, want c1", req.Events[0].Client)
	}
}

func TestHTTPPlugin_Observe_EmptyEvents(t *testing.T) {
	p := NewHTTPPlugin("test", "http://localhost:9999")
	err := p.Observe(context.Background(), nil)
	if err != nil {
		t.Errorf("empty events should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Observe_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err == nil {
		t.Error("Observe should return error on non-200 response")
	}
}

func TestHTTPPlugin_Observe_NotOk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": false}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err == nil {
		t.Error("Observe should return error when ok is false")
	}
}

func TestHTTPPlugin_Observe_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err == nil {
		t.Error("Observe should return error on invalid JSON response")
	}
}

func TestHTTPPlugin_CustomHeader(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.HeaderOption(http.Header{
		"X-Custom": []string{"my-value"},
	}))
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receivedHeader != "my-value" {
		t.Errorf("X-Custom header = %s, want my-value", receivedHeader)
	}
}

func TestHTTPPlugin_Observe_WithClient(t *testing.T) {
	// Ensure p.client is properly set by constructor and Observe doesn't
	// hit the dead nil check.
	p := NewHTTPPlugin("test", "http://example.com")
	if p.(*httpPlugin).client == nil {
		t.Fatal("client should not be nil after construction")
	}
}

// Test that httpPlugin satisfies observer.Observer
var _ observer.Observer = (*httpPlugin)(nil)
