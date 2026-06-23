package parsing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
)

// writeTestCertKey writes a self-signed cert/key pair to the given file paths.
// The cert is NOT persisted via the defaultCertDir mechanism — it simulates
// user-provided cert.pem / key.pem in a working directory.
func writeTestCertKey(t *testing.T, certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cwd-test.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

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
	// Use a temp dir so the test is isolated and doesn't touch $HOME/.gost
	testDefaultCertDir = t.TempDir()
	t.Cleanup(func() { testDefaultCertDir = "" })

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

	// Verify that the certificate and key files were persisted.
	certFile := filepath.Join(testDefaultCertDir, "auto-ca-cert.pem")
	keyFile := filepath.Join(testDefaultCertDir, "auto-ca-key.pem")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Fatal("cert file was not persisted")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("key file was not persisted")
	}
}

func TestBuildDefaultTLSConfig_WithOptions(t *testing.T) {
	testDefaultCertDir = t.TempDir()
	t.Cleanup(func() { testDefaultCertDir = "" })

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

func TestBuildDefaultTLSConfig_TwoCallsSameCerts(t *testing.T) {
	testDefaultCertDir = t.TempDir()
	t.Cleanup(func() { testDefaultCertDir = "" })

	cfg1, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}
	cfg2, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if len(cfg1.Certificates) == 0 || len(cfg2.Certificates) == 0 {
		t.Fatal("expected certificates in both configs")
	}

	// Both calls should return the SAME persisted certificate.
	c1 := cfg1.Certificates[0].Certificate[0]
	c2 := cfg2.Certificates[0].Certificate[0]
	if !bytes.Equal(c1, c2) {
		t.Fatal("expected same certificate from two calls (persisted)")
	}
}

func TestBuildDefaultTLSConfig_PersistsAndReloads(t *testing.T) {
	testDefaultCertDir = t.TempDir()
	defer func() { testDefaultCertDir = "" }()

	// First call generates and persists.
	cfg1, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	// Verify files exist on disk.
	certFile := filepath.Join(testDefaultCertDir, "auto-ca-cert.pem")
	keyFile := filepath.Join(testDefaultCertDir, "auto-ca-key.pem")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Fatal("cert file was not persisted after first call")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("key file was not persisted after first call")
	}

	// Second call loads the persisted cert.
	cfg2, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	c1 := cfg1.Certificates[0].Certificate[0]
	c2 := cfg2.Certificates[0].Certificate[0]
	if !bytes.Equal(c1, c2) {
		t.Fatal("expected same certificate on reload (persisted)")
	}
}

func TestBuildDefaultTLSConfig_FallsBackWhenWriteBlocked(t *testing.T) {
	// Point to a directory that can't be created (e.g. a file path).
	// We use a path under /proc on Linux which is a read-only filesystem.
	testDefaultCertDir = "/proc/doesnotexist/certdir"
	defer func() { testDefaultCertDir = "" }()

	tlsCfg, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error (should fall back to in-memory): %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil config even when write fails")
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate from fallback")
	}
}

// TestBuildDefaultTLSConfig_CWDTakesPriority verifies that when cert.pem and
// key.pem exist in the current working directory, they take precedence over
// both the persisted certificate and auto-generation.
func TestBuildDefaultTLSConfig_CWDTakesPriority(t *testing.T) {
	// Create a temp dir with cert.pem / key.pem.
	cwd := t.TempDir()
	writeTestCertKey(t, filepath.Join(cwd, "cert.pem"), filepath.Join(cwd, "key.pem"))

	// Also set up a persisted cert directory.
	testDefaultCertDir = t.TempDir()
	defer func() { testDefaultCertDir = "" }()

	// Pre-populate persisted cert so we can prove CWD wins.
	_, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("pre-populate persisted cert: %v", err)
	}

	// Change to the CWD that has cert.pem / key.pem.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origDir)

	// BuildDefaultTLSConfig should load CWD cert, not the persisted one.
	tlsCfg, err := BuildDefaultTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}

	// Load CWD cert directly and compare.
	cwdCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		t.Fatalf("load CWD cert: %v", err)
	}
	got := tlsCfg.Certificates[0].Certificate[0]
	want := cwdCert.Certificate[0]
	if !bytes.Equal(got, want) {
		t.Fatal("CWD certificate was not used (persisted or auto-generated cert took priority)")
	}

	// Load persisted cert to prove it's different from CWD cert.
	persistedCert, err := tls.LoadX509KeyPair(
		filepath.Join(testDefaultCertDir, "auto-ca-cert.pem"),
		filepath.Join(testDefaultCertDir, "auto-ca-key.pem"),
	)
	if err != nil {
		t.Fatalf("load persisted cert: %v", err)
	}
	if bytes.Equal(got, persistedCert.Certificate[0]) {
		t.Fatal("CWD cert should differ from persisted cert; test setup issue")
	}
}
