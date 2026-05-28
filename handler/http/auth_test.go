package http

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
)

// stubAuther implements auth.Authenticator for testing.
type stubAuther struct {
	accept bool
	id     string
}

func (a *stubAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	return a.id, a.accept
}


// --- Authenticator tests (synchronous — no net.Pipe or goroutines) ---

func TestAuthenticate_NoAuther(t *testing.T) {
	a := &Authenticator{}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if !result.OK {
		t.Fatal("expected OK=true when no Auther")
	}
	if result.ClientID != "" {
		t.Errorf("expected empty client ID, got %q", result.ClientID)
	}
}

func TestAuthenticate_Success(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: true, id: "testuser"},
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dGVzdHVzZXI6cGFzc3dvcmQ=")
	result := a.Authenticate(context.Background(), req)
	if !result.OK {
		t.Fatal("expected auth success")
	}
	if result.ClientID != "testuser" {
		t.Errorf("got id %q, want testuser", result.ClientID)
	}
}

func TestAuthenticate_Failure(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		Realm:  "gost",
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dGVzdHVzZXI6cGFzc3dvcmQ=")
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	if result.Response == nil {
		t.Fatal("expected non-nil response on failure")
	}
	if result.Response.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("got status %d, want %d", result.Response.StatusCode, http.StatusProxyAuthRequired)
	}
	if result.Response.Header.Get("Proxy-Authenticate") == "" {
		t.Error("expected Proxy-Authenticate header")
	}
}

func TestAuthenticate_ProbeResistanceCode(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		PR:     &probeResistance{Type: "code", Value: "404"},
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	if result.Response.StatusCode != 404 {
		t.Errorf("got status %d, want 404", result.Response.StatusCode)
	}
}

func TestAuthenticate_ProbeResistanceKnock(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		Realm:  "gost",
		PR:     &probeResistance{Type: "code", Value: "404", Knock: "secret.example.com"},
	}
	req, _ := http.NewRequest("GET", "http://secret.example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	// Knock matches, probe resistance bypassed → 407
	if result.Response.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("got status %d, want %d (knock matched, bypass probe resistance)",
			result.Response.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticate_ProbeResistanceKnockMismatch(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		PR:     &probeResistance{Type: "code", Value: "503", Knock: "secret.example.com"},
	}
	req, _ := http.NewRequest("GET", "http://other.example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	// Knock doesn't match, probe resistance activates → 503
	if result.Response.StatusCode != 503 {
		t.Errorf("got status %d, want 503", result.Response.StatusCode)
	}
}

func TestAuthenticate_ProbeResistanceKnockMultiMatch(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		Realm:  "gost",
		PR: &probeResistance{
			Type:  "code",
			Value: "404",
			Knock: "a.example.com, b.example.com, secret.example.com",
		},
	}
	req, _ := http.NewRequest("GET", "http://secret.example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	if result.Response.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("got status %d, want %d (knock matched, bypass probe resistance)",
			result.Response.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticate_ProbeResistanceKnockMultiMismatch(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		PR: &probeResistance{
			Type:  "code",
			Value: "503",
			Knock: "a.example.com, b.example.com",
		},
	}
	req, _ := http.NewRequest("GET", "http://other.example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	if result.Response.StatusCode != 503 {
		t.Errorf("got status %d, want 503", result.Response.StatusCode)
	}
}

func TestAuthenticate_ProbeResistanceHost(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		PR:     &probeResistance{Type: "host", Value: "1.2.3.4:80"},
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	if result.PipeTo != "1.2.3.4:80" {
		t.Errorf("got PipeTo %q, want 1.2.3.4:80", result.PipeTo)
	}
	if result.Response != nil {
		t.Error("expected nil Response for host probe resistance")
	}
}

func TestAuthenticate_ProbeResistanceInvalidCode(t *testing.T) {
	a := &Authenticator{
		Auther: &stubAuther{accept: false},
		Realm:  "gost",
		PR:     &probeResistance{Type: "code", Value: "not-a-number"},
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	result := a.Authenticate(context.Background(), req)
	if result.OK {
		t.Fatal("expected auth failure")
	}
	// Invalid code → status stays at 503 (the probe resistance default)
	if result.Response.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d (invalid code keeps default 503)",
			result.Response.StatusCode, http.StatusServiceUnavailable)
	}
}

// --- knockMatch tests ---

func TestKnockMatch(t *testing.T) {
	tests := []struct {
		hostname string
		knock    string
		want     bool
	}{
		{"", "", false},
		{"example.com", "", false},
		{"example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true}, // case-insensitive
		{"example.com", "other.com", false},
		{"example.com", " one.example.com , example.com , two.example.com ", true},
		{"example.com", " one.example.com, two.example.com ", false},
		{"", "example.com", false},
		{"example.com", " example.com , , two.example.com ", true}, // empty entry between commas
	}
	for _, tt := range tests {
		got := knockMatch(tt.hostname, tt.knock)
		if got != tt.want {
			t.Errorf("knockMatch(%q, %q) = %v, want %v", tt.hostname, tt.knock, got, tt.want)
		}
	}
}

// --- checkRateLimit tests ---

func TestCheckRateLimit_NoLimiter(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("checkRateLimit should return true when no limiter is set")
	}
}

func TestCheckRateLimit_WithLimiter(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			RateLimiter: &stubRateLimiter{allow: false, limiter: &stubLimiter{allow: false}},
		},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	if h.checkRateLimit(addr) {
		t.Error("checkRateLimit should return false when limiter denies")
	}
}

func TestCheckRateLimit_Allow(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			RateLimiter: &stubRateLimiter{allow: true, limiter: &stubLimiter{allow: true}},
		},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	if !h.checkRateLimit(addr) {
		t.Error("checkRateLimit should return true when limiter allows")
	}
}

func TestCheckRateLimit_NilAddr(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			RateLimiter: &stubRateLimiter{allow: true, limiter: &stubLimiter{allow: true}},
		},
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("checkRateLimit panicked with nil addr: %v", r)
			}
		}()
		_ = h.checkRateLimit(nil)
	}()
}

// --- Stub implementations (used by multiple test files) ---

// stubRateLimiter implements rate.RateLimiter for testing.
type stubRateLimiter struct {
	allow   bool
	limiter *stubLimiter
}

func (l *stubRateLimiter) Limiter(key string) rate.Limiter {
	if key == "" {
		return nil
	}
	return l.limiter
}

// stubLimiter implements rate.Limiter for testing.
type stubLimiter struct {
	allow bool
}

func (l *stubLimiter) Allow(n int) bool  { return l.allow }
func (l *stubLimiter) AllowN(n int) bool { return l.allow }
func (l *stubLimiter) Limit() float64    { return 0 }

// testTrafficLimiter implements traffic.TrafficLimiter for testing.
type testTrafficLimiter struct{}

func (l *testTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return &testTLimiter{}
}
func (l *testTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return &testTLimiter{}
}
func (l *testTrafficLimiter) InOut(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return &testTLimiter{}
}

type testTLimiter struct{}

func (l *testTLimiter) Wait(ctx context.Context, n int) int { return n }
func (l *testTLimiter) Limit() int                          { return 0 }
func (l *testTLimiter) Set(n int)                           {}
