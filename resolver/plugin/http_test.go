package resolver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/plugin"
	xlogger "github.com/go-gost/x/logger"
)

func init() {
	logger.SetDefault(xlogger.Nop())
}

func TestHTTPPlugin_ResolveSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json content-type, got %s", ct)
		}

		var req httpPluginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Host != "example.com" {
			t.Errorf("expected host example.com, got %s", req.Host)
		}

		resp := httpPluginResponse{
			IPs: []string{"10.0.0.1", "10.0.0.2"},
			OK:  true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.TimeoutOption(5*time.Second))
	ips, err := p.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("first IP = %v, want 10.0.0.1", ips[0])
	}
	if !ips[1].Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("second IP = %v, want 10.0.0.2", ips[1])
	}
}

func TestHTTPPlugin_ResolveEmptyIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := httpPluginResponse{IPs: []string{}, OK: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.TimeoutOption(5*time.Second))
	ips, err := p.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("expected 0 IPs, got %d: %v", len(ips), ips)
	}
}

func TestHTTPPlugin_ResolveNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := httpPluginResponse{IPs: []string{}, OK: false}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.TimeoutOption(5*time.Second))
	_, err := p.Resolve(context.Background(), "ip", "example.com")
	if err == nil {
		t.Fatal("expected error when OK=false")
	}
}

func TestHTTPPlugin_ResolveInvalidIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := httpPluginResponse{
			IPs: []string{"not-an-ip", "10.0.0.1"},
			OK:  true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.TimeoutOption(5*time.Second))
	ips, err := p.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 valid IP (invalid skipped), got %d: %v", len(ips), ips)
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP = %v, want 10.0.0.1", ips[0])
	}
}

func TestHTTPPlugin_ResolveHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.TimeoutOption(5*time.Second))
	_, err := p.Resolve(context.Background(), "ip", "example.com")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestHTTPPlugin_ResolveCancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		resp := httpPluginResponse{IPs: []string{"10.0.0.1"}, OK: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.TimeoutOption(10*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Resolve(ctx, "ip", "example.com")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestHTTPPlugin_ResolveConnectionRefused(t *testing.T) {
	// Use a port that's not listening
	p := NewHTTPPlugin("test", "http://127.0.0.1:1/nonexistent", plugin.TimeoutOption(100*time.Millisecond))
	_, err := p.Resolve(context.Background(), "ip", "example.com")
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestHTTPPlugin_NilClient(t *testing.T) {
	p := &httpPlugin{client: nil, log: xlogger.Nop()}
	ips, err := p.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("expected no IPs with nil client, got %v", ips)
	}
}

func TestHTTPPlugin_CustomHeader(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		resp := httpPluginResponse{IPs: []string{"10.0.0.1"}, OK: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer test-token")
	p := NewHTTPPlugin("test", srv.URL, plugin.HeaderOption(headers))

	_, err := p.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want %q", receivedAuth, "Bearer test-token")
	}
}

func TestHTTPPlugin_ClientID(t *testing.T) {
	var receivedClient string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req httpPluginRequest
		json.NewDecoder(r.Body).Decode(&req)
		receivedClient = req.Client
		resp := httpPluginResponse{IPs: []string{"10.0.0.1"}, OK: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	_, err := p.Resolve(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Client ID is empty when not set in context
	if receivedClient != "" {
		t.Errorf("expected empty client, got %q", receivedClient)
	}
}
