package http

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
)

// stubAuther implements auth.Authenticator for testing.
type stubAuther struct {
	accept bool
	id     string
}

func (a *stubAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	return a.id, a.accept
}

// testLogger implements logger.Logger for testing.
type testLogger struct{}

func (l *testLogger) WithFields(fields map[string]any) logger.Logger             { return l }
func (l *testLogger) Debug(args ...any)                                           {}
func (l *testLogger) Debugf(format string, args ...any)                           {}
func (l *testLogger) Info(args ...any)                                            {}
func (l *testLogger) Infof(format string, args ...any)                            {}
func (l *testLogger) Warn(args ...any)                                            {}
func (l *testLogger) Warnf(format string, args ...any)                            {}
func (l *testLogger) Error(args ...any)                                           {}
func (l *testLogger) Errorf(format string, args ...any)                           {}
func (l *testLogger) Fatal(args ...any)                                           {}
func (l *testLogger) Fatalf(format string, args ...any)                           {}
func (l *testLogger) GetLevel() logger.LogLevel                                    { return logger.InfoLevel }
func (l *testLogger) IsLevelEnabled(level logger.LogLevel) bool                    { return false }
func (l *testLogger) Trace(args ...any)                                            {}
func (l *testLogger) Tracef(format string, args ...any)                            {}

func TestAuthenticate_NoAuther(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	// Read the response from authenticate in a goroutine
	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	// Client side: read the response back
	// With no auther, authenticate returns early with ok=true, no response written
	br := bufio.NewReader(client)
	// The response shouldn't be written when auth succeeds
	time.Sleep(50 * time.Millisecond)
	// Connection should be clean - no data to read
	_ = br
}

func TestAuthenticate_Success(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: true, id: "testuser"},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dGVzdHVzZXI6cGFzc3dvcmQ=") // testuser:password
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		id, ok := h.authenticate(context.Background(), server, req, resp, &testLogger{})
		if !ok {
			t.Error("expected auth success")
		}
		if id != "testuser" {
			t.Errorf("got id %q, want %q", id, "testuser")
		}
	}()

	time.Sleep(50 * time.Millisecond)
	// Auth succeeded, no response written to client
	_ = client
	<-done
}

func TestAuthenticate_Failure(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: false},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dGVzdHVzZXI6cGFzc3dvcmQ=")
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	// Read the 407 response
	br := bufio.NewReader(client)
	r, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("failed to read auth response: %v", err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("got status %d, want %d", r.StatusCode, http.StatusProxyAuthRequired)
	}
	if r.Header.Get("Proxy-Authenticate") == "" {
		t.Error("expected Proxy-Authenticate header")
	}
}

func TestAuthenticate_ProbeResistanceCode(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: false},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.probeResistance = &probeResistance{Type: "code", Value: "404"}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	br := bufio.NewReader(client)
	r, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("failed to read probe resistance response: %v", err)
	}
	defer r.Body.Close()

	if r.StatusCode != 404 {
		t.Errorf("got status %d, want 404", r.StatusCode)
	}
}

func TestAuthenticate_ProbeResistanceKnock(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: false},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	// Knock matches - probe resistance should be bypassed, fall through to 407
	h.md.probeResistance = &probeResistance{Type: "code", Value: "404", Knock: "secret.example.com"}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://secret.example.com/", nil)
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	br := bufio.NewReader(client)
	r, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer r.Body.Close()

	// Knock matches, so probe resistance is bypassed, get normal 407
	if r.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("got status %d, want %d (knock matched, should bypass probe resistance)", r.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticate_ProbeResistanceKnockMismatch(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: false},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	// Knock doesn't match - probe resistance should activate
	h.md.probeResistance = &probeResistance{Type: "code", Value: "503", Knock: "secret.example.com"}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://other.example.com/", nil)
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	br := bufio.NewReader(client)
	r, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer r.Body.Close()

	// Knock doesn't match, probe resistance activates
	if r.StatusCode != 503 {
		t.Errorf("got status %d, want 503", r.StatusCode)
	}
}

func TestAuthenticate_ProbeResistanceKnockMultiMatch(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: false},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	// Third entry matches — probe resistance should be bypassed, return 407
	h.md.probeResistance = &probeResistance{
		Type:  "code",
		Value: "404",
		Knock: "a.example.com, b.example.com, secret.example.com",
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://secret.example.com/", nil)
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	br := bufio.NewReader(client)
	r, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("got status %d, want %d (knock matched, should bypass probe resistance)", r.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticate_ProbeResistanceKnockMultiMismatch(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Auther: &stubAuther{accept: false},
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	// No entry matches — probe resistance should activate
	h.md.probeResistance = &probeResistance{
		Type:  "code",
		Value: "503",
		Knock: "a.example.com, b.example.com",
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req, _ := http.NewRequest("GET", "http://other.example.com/", nil)
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}

	go func() {
		h.authenticate(context.Background(), server, req, resp, &testLogger{})
	}()

	br := bufio.NewReader(client)
	r, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer r.Body.Close()

	if r.StatusCode != 503 {
		t.Errorf("got status %d, want 503", r.StatusCode)
	}
}

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
	// Create a handler with a rate limiter that blocks everything
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

	// Nil addr should not panic - robustness check
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("checkRateLimit panicked with nil addr: %v", r)
			}
		}()
		// This may panic if addr.String() is called on nil - that's a String() panic, not ours
		// But we should guard against it
		_ = h.checkRateLimit(nil) //nolint
	}()
}

// testRecorderObject is a recorder.RecorderObject for testing.
var testRecorderObject = struct {
	Record  string
	Options *testRecorderOptions
}{Record: "serviceHandler"}

type testRecorderOptions struct {
	HTTPBody bool
}

// stubRateLimiter implements rate.RateLimiter for testing.
type stubRateLimiter struct {
	allow    bool
	limiter  *stubLimiter
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

func (l *stubLimiter) Allow(n int) bool     { return l.allow }
func (l *stubLimiter) AllowN(n int) bool    { return l.allow }
func (l *stubLimiter) Limit() float64       { return 0 }

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

