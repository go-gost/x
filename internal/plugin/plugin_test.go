package plugin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewGRPCConn_NilOpts(t *testing.T) {
	conn, err := NewGRPCConn("localhost:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	conn.Close()
}

func TestNewGRPCConn_NoTLS(t *testing.T) {
	conn, err := NewGRPCConn("localhost:0", &Options{})
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	conn.Close()
}

func TestNewGRPCConn_WithTLS(t *testing.T) {
	conn, err := NewGRPCConn("localhost:0", &Options{
		TLSConfig: nil, // nil TLSConfig -> insecure
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	conn.Close()
}

func TestNewHTTPClient_NilOpts(t *testing.T) {
	c := NewHTTPClient(nil)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewHTTPClient_Defaults(t *testing.T) {
	c := NewHTTPClient(&Options{})
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Timeout != 0 {
		t.Errorf("expected zero timeout, got %v", c.Timeout)
	}
}

func TestNewHTTPClient_WithTimeout(t *testing.T) {
	c := NewHTTPClient(&Options{Timeout: 5 * time.Second})
	if c.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", c.Timeout)
	}
}

func TestHTTPClientTransport_Nil(t *testing.T) {
	if tr := HTTPClientTransport(nil); tr != nil {
		t.Error("expected nil transport for nil client")
	}
}

func TestHTTPClientTransport_Valid(t *testing.T) {
	c := NewHTTPClient(&Options{})
	tr := HTTPClientTransport(c)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	// Verify we can call CloseIdleConnections without panic.
	tr.CloseIdleConnections()
}

func TestOption(t *testing.T) {
	opts := &Options{}
	TokenOption("tok")(opts)
	TLSConfigOption(nil)(opts)
	HeaderOption(http.Header{"X": []string{"y"}})(opts)
	TimeoutOption(time.Second)(opts)

	if opts.Token != "tok" {
		t.Errorf("expected Token 'tok', got %q", opts.Token)
	}
	if opts.Timeout != time.Second {
		t.Errorf("expected 1s timeout, got %v", opts.Timeout)
	}
	if opts.Header.Get("X") != "y" {
		t.Errorf("expected header X=y, got %v", opts.Header)
	}
}

func TestNewHTTPClient_TransportTLSConfig(t *testing.T) {
	// nil TLSConfig — transport should still exist.
	c := NewHTTPClient(&Options{})
	tr := HTTPClientTransport(c)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.TLSClientConfig != nil {
		t.Error("expected nil TLSClientConfig")
	}
}

func TestNewHTTPClient_WithToken_SetsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClient(&Options{Token: "secret-token"})
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if want := "Bearer secret-token"; gotAuth != want {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, want)
	}
}

func TestNewHTTPClient_NoToken_NoAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClient(&Options{})
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotAuth != "" {
		t.Errorf("Authorization header: got %q, want empty", gotAuth)
	}
}

func TestNewHTTPClient_Token_DoesNotOverrideExistingAuthorization(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClient(&Options{Token: "from-options"})
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer caller-set")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if want := "Bearer caller-set"; gotAuth != want {
		t.Errorf("Authorization header: got %q, want %q (caller's value must be preserved)", gotAuth, want)
	}
}

func TestNewHTTPClient_Token_DoesNotMutateCallerRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClient(&Options{Token: "secret-token"})
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("caller's request Authorization header was mutated to %q; expected empty", got)
	}
}

func TestHTTPClientTransport_UnwrapsTokenTransport(t *testing.T) {
	c := NewHTTPClient(&Options{Token: "tok"})
	tr := HTTPClientTransport(c)
	if tr == nil {
		t.Fatal("expected non-nil *http.Transport unwrapped from tokenTransport")
	}
	tr.CloseIdleConnections()
}
