package service

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
)

// testAuther is a simple auth.Authenticator for testing.
type testAuther struct {
	allowUser, allowPass string
}

func (a *testAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if user == a.allowUser && password == a.allowPass {
		return user, true
	}
	return "", false
}

func TestNewServiceDefaultPath(t *testing.T) {
	s, err := NewService("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	defer s.Close()

	if s.Addr() == nil {
		t.Error("Addr should not be nil")
	}
}

func TestNewServiceDefaultNetwork(t *testing.T) {
	s, err := NewService("", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewService with empty network error: %v", err)
	}
	defer s.Close()

	if s.Addr() == nil {
		t.Error("Addr should not be nil")
	}
}

func TestNewServiceCustomPath(t *testing.T) {
	s, err := NewService("tcp", "127.0.0.1:0", PathOption("/custom"))
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	defer s.Close()

	// Serve in background for a short time.
	go s.Serve()
	time.Sleep(50 * time.Millisecond)

	// Default path should 404.
	resp, err := http.Get("http://" + s.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /metrics: expected 404, got %d", resp.StatusCode)
	}

	// Custom path should 200.
	resp2, err := http.Get("http://" + s.Addr().String() + "/custom")
	if err != nil {
		t.Fatalf("GET /custom error: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /custom: expected 200, got %d", resp2.StatusCode)
	}
}

func TestNewServiceWithAuth(t *testing.T) {
	auther := &testAuther{allowUser: "admin", allowPass: "secret"}
	s, err := NewService("tcp", "127.0.0.1:0", AutherOption(auther))
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	defer s.Close()

	go s.Serve()
	time.Sleep(50 * time.Millisecond)

	addr := "http://" + s.Addr().String() + "/metrics"

	// No credentials should be 401.
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without credentials, got %d", resp.StatusCode)
	}

	// Wrong credentials should be 401.
	req, _ := http.NewRequest("GET", addr, nil)
	req.SetBasicAuth("admin", "wrong")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with wrong auth error: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong credentials, got %d", resp2.StatusCode)
	}

	// Correct credentials should be 200.
	req3, _ := http.NewRequest("GET", addr, nil)
	req3.SetBasicAuth("admin", "secret")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET with correct auth error: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct credentials, got %d", resp3.StatusCode)
	}
}

func TestServiceClose(t *testing.T) {
	svc, err := NewService("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	s := svc.(*metricService)

	if s.IsClosed() {
		t.Error("IsClosed should be false before Close")
	}

	// Serve in background.
	go s.Serve()
	time.Sleep(50 * time.Millisecond)

	err = s.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}

	if !s.IsClosed() {
		t.Error("IsClosed should be true after Close")
	}

	// Double close should be safe.
	err = s.Close()
	if err != nil {
		t.Errorf("second Close error: %v", err)
	}
}

func TestServiceServeReturnsOnClose(t *testing.T) {
	s, err := NewService("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Serve()
	}()

	time.Sleep(50 * time.Millisecond)
	s.Close()

	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s after Close")
	}
}

func TestNewServiceAddr(t *testing.T) {
	s, err := NewService("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	defer s.Close()

	addr := s.Addr()
	if addr == nil {
		t.Fatal("Addr should not be nil")
	}
	if _, ok := addr.(*net.TCPAddr); !ok {
		t.Errorf("expected *net.TCPAddr, got %T", addr)
	}
}

func TestNewServiceListenError(t *testing.T) {
	// Using an invalid address should cause a listen error.
	_, err := NewService("invalid", "127.0.0.1:0")
	if err == nil {
		t.Error("expected error for invalid network, got nil")
	}
}
