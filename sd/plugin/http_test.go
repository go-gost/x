package sd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-gost/core/sd"
	"github.com/go-gost/x/internal/plugin"
)

// --- NewHTTPPlugin ---

func TestNewHTTPPlugin_ReturnsNonNil(t *testing.T) {
	p := NewHTTPPlugin("test", "http://localhost:8080")
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

// --- Register ---

func TestHTTPPlugin_Register_NilClient(t *testing.T) {
	p := &httpPlugin{}
	if err := p.Register(context.Background(), &sd.Service{ID: "1"}); err != nil {
		t.Errorf("nil client Register should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Register_NilService(t *testing.T) {
	p := &httpPlugin{client: &http.Client{}}
	if err := p.Register(context.Background(), nil); err != nil {
		t.Errorf("nil service Register should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Register_Success(t *testing.T) {
	var gotBody sdService
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	svc := &sd.Service{ID: "svc-1", Name: "test", Node: "n1", Network: "tcp", Address: "10.0.0.1:80"}
	if err := p.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if gotBody.ID != "svc-1" {
		t.Errorf("body ID = %s, want svc-1", gotBody.ID)
	}
	if gotBody.Network != "tcp" {
		t.Errorf("body Network = %s, want tcp", gotBody.Network)
	}
}

func TestHTTPPlugin_Register_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Register(context.Background(), &sd.Service{ID: "1"})
	if err == nil {
		t.Fatal("Register should return error on non-200 response")
	}
}

// --- Deregister ---

func TestHTTPPlugin_Deregister_NilClient(t *testing.T) {
	p := &httpPlugin{}
	if err := p.Deregister(context.Background(), &sd.Service{ID: "1"}); err != nil {
		t.Errorf("nil client Deregister should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Deregister_NilService(t *testing.T) {
	p := &httpPlugin{client: &http.Client{}}
	if err := p.Deregister(context.Background(), nil); err != nil {
		t.Errorf("nil service Deregister should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Deregister_Success(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	if err := p.Deregister(context.Background(), &sd.Service{ID: "svc-1"}); err != nil {
		t.Fatalf("Deregister failed: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
}

func TestHTTPPlugin_Deregister_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Deregister(context.Background(), &sd.Service{ID: "1"})
	if err == nil {
		t.Fatal("Deregister should return error on non-200 response")
	}
}

// --- Renew ---

func TestHTTPPlugin_Renew_NilClient(t *testing.T) {
	p := &httpPlugin{}
	if err := p.Renew(context.Background(), &sd.Service{ID: "1"}); err != nil {
		t.Errorf("nil client Renew should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Renew_NilService(t *testing.T) {
	p := &httpPlugin{client: &http.Client{}}
	if err := p.Renew(context.Background(), nil); err != nil {
		t.Errorf("nil service Renew should return nil, got %v", err)
	}
}

func TestHTTPPlugin_Renew_Success(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	if err := p.Renew(context.Background(), &sd.Service{ID: "svc-1"}); err != nil {
		t.Fatalf("Renew failed: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
}

func TestHTTPPlugin_Renew_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Renew(context.Background(), &sd.Service{ID: "1"})
	if err == nil {
		t.Fatal("Renew should return error on non-200 response")
	}
}

// --- Get ---

func TestHTTPPlugin_Get_NilClient(t *testing.T) {
	p := &httpPlugin{}
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Errorf("nil client Get should return nil error, got %v", err)
	}
	if services != nil {
		t.Errorf("nil client Get should return nil services, got %v", services)
	}
}

func TestHTTPPlugin_Get_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if name := r.URL.Query().Get("name"); name != "my-svc" {
			t.Errorf("name query = %s, want my-svc", name)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"services":[
			{"id":"1","name":"my-svc","node":"n1","network":"tcp","address":"10.0.0.1:80"},
			{"id":"2","name":"my-svc","node":"n2","network":"udp","address":"10.0.0.2:53"}
		]}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	services, err := p.Get(context.Background(), "my-svc")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0].ID != "1" || services[0].Network != "tcp" {
		t.Errorf("service[0] = %+v, want ID=1 Network=tcp", services[0])
	}
	if services[1].ID != "2" || services[1].Network != "udp" {
		t.Errorf("service[1] = %+v, want ID=2 Network=udp", services[1])
	}
}

func TestHTTPPlugin_Get_SkipsNilServices(t *testing.T) {
	// The JSON response has a null entry in the services array. After decoding,
	// Get should skip nil entries.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"services":[{"id":"1","name":"test"},null,{"id":"3","name":"test"}]}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 non-nil services, got %d", len(services))
	}
}

func TestHTTPPlugin_Get_EmptyServices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"services":[]}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services))
	}
}

func TestHTTPPlugin_Get_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	services, err := p.Get(context.Background(), "test")
	if err == nil {
		t.Fatal("Get should return error on non-200 response")
	}
	if services != nil {
		t.Errorf("expected nil services on error, got %v", services)
	}
}

func TestHTTPPlugin_Get_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	_, err := p.Get(context.Background(), "test")
	if err == nil {
		t.Fatal("Get should return error on invalid JSON response")
	}
}

// --- Custom Header ---

func TestHTTPPlugin_CustomHeader(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.HeaderOption(http.Header{
		"X-Custom": []string{"my-value"},
	}))
	err := p.Register(context.Background(), &sd.Service{ID: "1", Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if receivedHeader != "my-value" {
		t.Errorf("X-Custom header = %s, want my-value", receivedHeader)
	}
}

// --- Context cancellation ---

func TestHTTPPlugin_Register_CanceledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := NewHTTPPlugin("test", srv.URL)
	err := p.Register(ctx, &sd.Service{ID: "1"})
	if err == nil {
		t.Error("Register should return error with canceled context")
	}
}

// --- Interface assertion ---

var _ sd.SD = (*httpPlugin)(nil)
