package local

import (
	"os"
	"testing"
	"time"

	xmd "github.com/go-gost/x/metadata"
)

// ---------------------------------------------------------------------------
// parseMetadata
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
	if h.md.sniffing {
		t.Error("expected sniffing disabled by default")
	}
}

func TestParseMetadata_CustomValues(t *testing.T) {
	h := newTestHandler()
	md := xmd.NewMetadata(map[string]any{
		"readTimeout":                   "60s",
		"http.keepalive":                true,
		"proxyProtocol":                 2,
		"sniffing":                      true,
		"sniffing.timeout":              "5s",
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
	if !h.md.httpKeepalive {
		t.Error("expected httpKeepalive true")
	}
	if h.md.proxyProtocol != 2 {
		t.Errorf("expected proxyProtocol 2, got %d", h.md.proxyProtocol)
	}
	if !h.md.sniffing {
		t.Error("expected sniffing true")
	}
	if h.md.sniffingTimeout != 5*time.Second {
		t.Errorf("expected 5s sniffingTimeout, got %v", h.md.sniffingTimeout)
	}
	if !h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket true")
	}
	if h.md.sniffingWebsocketSampleRate != 0.75 {
		t.Errorf("expected 0.75, got %f", h.md.sniffingWebsocketSampleRate)
	}
}

// ---------------------------------------------------------------------------
// parseMetadata — cert/key
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
