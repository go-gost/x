package exchanger

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	xlogger "github.com/go-gost/x/logger"
)

func TestNewExchanger_UDP(t *testing.T) {
	ex, err := NewExchanger("1.1.1.1:53", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.network != "udp" {
		t.Errorf("expected udp network, got %q", e.network)
	}
	if e.addr != "1.1.1.1:53" {
		t.Errorf("expected addr 1.1.1.1:53, got %q", e.addr)
	}
}

func TestNewExchanger_UDPDefaultPort(t *testing.T) {
	ex, err := NewExchanger("1.1.1.1", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.addr != "1.1.1.1:53" {
		t.Errorf("expected addr 1.1.1.1:53 (default port), got %q", e.addr)
	}
}

func TestNewExchanger_TCP(t *testing.T) {
	ex, err := NewExchanger("tcp://1.1.1.1:53", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.network != "tcp" {
		t.Errorf("expected tcp network, got %q", e.network)
	}
}

func TestNewExchanger_TLS(t *testing.T) {
	ex, err := NewExchanger("tls://1.1.1.1:853", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.network != "tcp" {
		t.Errorf("expected tls→tcp network, got %q", e.network)
	}
	if e.options.tlsConfig == nil {
		t.Error("expected TLS config to be set")
	}
}

func TestNewExchanger_DoT(t *testing.T) {
	ex, err := NewExchanger("dot://1.1.1.1:853", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.network != "tcp" {
		t.Errorf("expected dot→tcp network, got %q", e.network)
	}
}

func TestNewExchanger_HTTPS(t *testing.T) {
	ex, err := NewExchanger("https://1.0.0.1/dns-query", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.network != "https" {
		t.Errorf("expected https network, got %q", e.network)
	}
	if e.client == nil {
		t.Error("expected HTTP client to be created for DoH")
	}
}

func TestNewExchanger_DefaultTimeout(t *testing.T) {
	ex, err := NewExchanger("1.1.1.1:53", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.options.timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", e.options.timeout)
	}
}

func TestNewExchanger_CustomTimeout(t *testing.T) {
	ex, err := NewExchanger("1.1.1.1:53", TimeoutOption(10*time.Second), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.options.timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", e.options.timeout)
	}
}

func TestNewExchanger_DefaultScheme(t *testing.T) {
	ex, err := NewExchanger("8.8.8.8", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.network != "udp" {
		t.Errorf("expected default to udp, got %q", e.network)
	}
}

func TestNewExchanger_InvalidURL(t *testing.T) {
	_, err := NewExchanger("://invalid", LoggerOption(xlogger.Nop()))
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestNewExchanger_CustomTLSConfig(t *testing.T) {
	customTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	ex, err := NewExchanger("tls://1.1.1.1:853", TLSConfigOption(customTLS), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.options.tlsConfig != customTLS {
		t.Error("expected custom TLS config to be preserved")
	}
}

func TestNewExchanger_SchemeNormalization(t *testing.T) {
	tests := []struct {
		addr    string
		network string
	}{
		{"udp://1.1.1.1:53", "udp"},
		{"tcp://1.1.1.1:53", "tcp"},
		{"tls://1.1.1.1:853", "tcp"},
		{"dot://1.1.1.1:853", "tcp"},
		{"https://1.1.1.1/dns-query", "https"},
		{"1.1.1.1:53", "udp"},        // bare addr → udp
		{"quic://1.1.1.1:53", "udp"}, // unknown → udp
	}
	for _, tt := range tests {
		ex, err := NewExchanger(tt.addr, LoggerOption(xlogger.Nop()))
		if err != nil {
			t.Errorf("NewExchanger(%q): %v", tt.addr, err)
			continue
		}
		e := ex.(*exchanger)
		if e.network != tt.network {
			t.Errorf("NewExchanger(%q): network=%q, want %q", tt.addr, e.network, tt.network)
		}
	}
}

func TestNewExchanger_String(t *testing.T) {
	ex, err := NewExchanger("udp://1.1.1.1:53", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ex.String() != "udp://1.1.1.1:53" {
		t.Errorf("String() = %q, want %q", ex.String(), "udp://1.1.1.1:53")
	}
}

func TestExchange_DialFailure(t *testing.T) {
	ex, err := NewExchanger("udp://127.0.0.1:1", TimeoutOption(100*time.Millisecond), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = ex.Exchange(context.Background(), []byte{0})
	if err == nil {
		t.Error("expected error for failed dial")
	}
}

func TestExchange_ContextCancelled(t *testing.T) {
	ex, err := NewExchanger("udp://1.1.1.1:53", TimeoutOption(5*time.Second), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = ex.Exchange(ctx, []byte{0})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestExchange_TimeoutExceeded(t *testing.T) {
	ex, err := NewExchanger("tcp://192.0.2.1:53", TimeoutOption(50*time.Millisecond), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	start := time.Now()
	_, err = ex.Exchange(context.Background(), []byte{0})
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

func TestDoHExchange_Failure(t *testing.T) {
	ex, err := NewExchanger("https://1.0.0.1/dns-query", TimeoutOption(100*time.Millisecond), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = ex.Exchange(context.Background(), []byte("not-a-dns-query"))
	if err == nil {
		t.Error("expected error for DoH exchange failure")
	}
}

func TestNewExchanger_BareAddr(t *testing.T) {
	ex, err := NewExchanger("8.8.8.8", LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if !strings.Contains(e.addr, "53") {
		t.Errorf("expected default port 53 in addr, got %q", e.addr)
	}
}

func TestNewExchanger_WithRouter(t *testing.T) {
	r := &stubRouter{}
	ex, err := NewExchanger("udp://1.1.1.1:53", RouterOption(r), LoggerOption(xlogger.Nop()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := ex.(*exchanger)
	if e.router != r {
		t.Error("expected custom router to be set")
	}
}

// stubRouter implements chain.Router for tests.
type stubRouter struct{}

func (s *stubRouter) Options() *chain.RouterOptions { return nil }
func (s *stubRouter) Dial(_ context.Context, _, _ string, _ ...chain.DialOption) (net.Conn, error) {
	return nil, net.UnknownNetworkError("stub")
}
func (s *stubRouter) Bind(_ context.Context, _, _ string, _ ...chain.BindOption) (net.Listener, error) {
	return nil, net.UnknownNetworkError("stub")
}
