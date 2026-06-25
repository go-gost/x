package sni

import (
	"os"
	"testing"
	"time"

	xmd "github.com/go-gost/x/metadata"
)

// ---------------------------------------------------------------------------
// parseMetadata — defaults
// ---------------------------------------------------------------------------

func TestParseMetadata_Defaults(t *testing.T) {
	h := newTestHandler()

	err := h.parseMetadata(xmd.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout <= 0 {
		t.Error("expected positive default readTimeout")
	}
	if h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket disabled by default")
	}
}

// ---------------------------------------------------------------------------
// parseMetadata — custom values
// ---------------------------------------------------------------------------

func TestParseMetadata_CustomValues(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"readTimeout":                   "60s",
		"hash":                          "host",
		"sniffing.websocket":            true,
		"sniffing.websocket.sampleRate": 0.75,
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout != 60*time.Second {
		t.Errorf("expected 60s, got %v", h.md.readTimeout)
	}
	if h.md.hash != "host" {
		t.Errorf("expected hash 'host', got '%s'", h.md.hash)
	}
	if !h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket true")
	}
	if h.md.sniffingWebsocketSampleRate != 0.75 {
		t.Errorf("expected 0.75, got %f", h.md.sniffingWebsocketSampleRate)
	}
}

func TestParseMetadata_ReadTimeoutDefault(t *testing.T) {
	h := newTestHandler()
	// A non-positive value should fall back to the 15s default.
	md := xmd.NewMetadata(map[string]any{
		"readTimeout": "0s",
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout != 15*time.Second {
		t.Errorf("expected 15s default, got %v", h.md.readTimeout)
	}
}

func TestParseMetadata_ReadTimeoutNegative(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"readTimeout": "-5s",
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout != 15*time.Second {
		t.Errorf("expected 15s default for negative value, got %v", h.md.readTimeout)
	}
}

// ---------------------------------------------------------------------------
// parseMetadata — MITM cert/key
// ---------------------------------------------------------------------------

func TestParseMetadata_MITMCertError(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": "/nonexistent/cert.pem",
		"mitm.keyFile":  "/nonexistent/key.pem",
	})
	err := h.parseMetadata(md)
	if err == nil {
		t.Fatal("expected error for non-existent cert file")
	}
}

func TestParseMetadata_MITMCertKeyMismatch(t *testing.T) {
	// Only certFile set, not keyFile — keys should not be loaded.
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": "/some/cert.pem",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.certificate != nil {
		t.Error("expected certificate to remain nil when keyFile not set")
	}
}

func TestParseMetadata_MITMCert(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	certFile := writeTempFile(t, "cert-*.pem", certPEM)
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "key-*.pem", keyPEM)
	defer os.Remove(keyFile)

	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.certFile": certFile,
		"mitm.keyFile":  keyFile,
		"mitm.alpn":     "h2",
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.certificate == nil {
		t.Error("expected certificate to be loaded")
	}
	if h.md.privateKey == nil {
		t.Error("expected privateKey to be loaded")
	}
	if h.md.alpn != "h2" {
		t.Errorf("expected alpn 'h2', got %s", h.md.alpn)
	}
}

func TestParseMetadata_MITMCertCACertFile(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	certFile := writeTempFile(t, "cert-*.pem", certPEM)
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "key-*.pem", keyPEM)
	defer os.Remove(keyFile)

	// Use the alternate "caCertFile"/"caKeyFile" key names.
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.caCertFile": certFile,
		"mitm.caKeyFile":  keyFile,
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.certificate == nil {
		t.Error("expected certificate to be loaded via caCertFile")
	}
	if h.md.privateKey == nil {
		t.Error("expected privateKey to be loaded via caKeyFile")
	}
}

func TestParseMetadata_MITMBypass(t *testing.T) {
	// Verify that mitm.bypass is parsed without error even when the named
	// bypass does not exist. The exact value depends on the global registry
	// state (other packages may have registered bypasses via init()).
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"mitm.bypass": "nonexistent-1769845",
	})

	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
