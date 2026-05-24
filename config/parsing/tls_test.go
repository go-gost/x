package parsing

import (
	"bytes"
	"crypto/tls"
	"io"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
)

func TestMain(m *testing.M) {
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))
	m.Run()
}

func TestSetDefaultTLSConfig(t *testing.T) {
	// Save and restore original
	orig := DefaultTLSConfig()
	defer SetDefaultTLSConfig(orig)

	cfg := &tls.Config{ServerName: "test.local"}
	SetDefaultTLSConfig(cfg)

	got := DefaultTLSConfig()
	if got == nil {
		t.Fatal("expected non-nil default TLS config")
	}
	if got.ServerName != "test.local" {
		t.Fatalf("ServerName = %q, want %q", got.ServerName, "test.local")
	}
}

func TestDefaultTLSConfig_InitiallyNil(t *testing.T) {
	orig := DefaultTLSConfig()
	defer SetDefaultTLSConfig(orig)

	// Store nil to reset
	SetDefaultTLSConfig(nil)

	got := DefaultTLSConfig()
	if got != nil {
		t.Fatal("expected nil after storing nil")
	}
}

func TestBuildDefaultTLSConfig_Nil(t *testing.T) {
	// BuildDefaultTLSConfig with nil should generate a self-signed cert
	tlsCfg, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}
}

func TestBuildDefaultTLSConfig_WithOptions(t *testing.T) {
	cfg := &config.TLSConfig{
		Validity:     0, // uses default
		Organization: "TestOrg",
		CommonName:   "test.example.com",
	}
	tlsCfg, err := BuildDefaultTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}
}

func TestBuildDefaultTLSConfig_TwoCallsDifferentCerts(t *testing.T) {
	cfg1, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg2, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg1.Certificates) == 0 || len(cfg2.Certificates) == 0 {
		t.Fatal("expected certificates in both configs")
	}

	// Each call generates a random cert; they should have different raw bytes.
	if len(cfg1.Certificates[0].Certificate) == 0 || len(cfg2.Certificates[0].Certificate) == 0 {
		t.Fatal("expected non-empty certificate raw bytes")
	}
	c1 := cfg1.Certificates[0].Certificate[0]
	c2 := cfg2.Certificates[0].Certificate[0]
	if bytes.Equal(c1, c2) {
		t.Fatal("expected different certificates from two calls")
	}
}
