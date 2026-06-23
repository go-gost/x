package parsing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	tls_util "github.com/go-gost/x/internal/util/tls"
)

var (
	defaultTLSConfig atomic.Value
)

// testDefaultCertDir overrides the default certificate directory in tests.
// It is set only from same-package test code and left empty in production.
var testDefaultCertDir string

// defaultCertDir returns the directory used for persisting auto-generated
// certificates. It uses testDefaultCertDir when set (for testing), otherwise
// returns $HOME/.gost/.
func defaultCertDir() string {
	if testDefaultCertDir != "" {
		return testDefaultCertDir
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return ".gost"
	}
	return filepath.Join(dir, ".gost")
}

// DefaultTLSConfig returns the global default TLS configuration used as a
// fallback when a listener or handler does not specify its own TLS settings.
// The returned config is a shared instance; callers that need to mutate it
// should clone it first.
func DefaultTLSConfig() *tls.Config {
	v, _ := defaultTLSConfig.Load().(*tls.Config)
	return v
}

// SetDefaultTLSConfig replaces the global default TLS configuration. It is safe
// to call from multiple goroutines.
func SetDefaultTLSConfig(cfg *tls.Config) {
	defaultTLSConfig.Store(cfg)
}

// BuildDefaultTLSConfig loads or generates the default TLS certificate and key
// from the given config.
//
// When explicit certificate files are configured (CertFile, KeyFile, or CAFile
// is non-empty) it loads them via tls_util.LoadDefaultConfig — the original
// behaviour preserved for backward compatibility.
//
// When no certificate files are configured (all three empty), it tries sources
// in this order:
//  1. cert.pem / key.pem in the current working directory (backward compatible)
//  2. auto-ca-cert.pem / auto-ca-key.pem under $HOME/.gost/ (persisted)
//  3. If none found, generates a new ECDSA P-256 CA certificate, persists it
//     to $HOME/.gost/, and uses it.
//
// If cfg is nil an empty TLSConfig is used (equivalent to no explicit files),
// so the CWD → persisted → generate path is taken.
func BuildDefaultTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	log := logger.Default()

	if cfg == nil {
		cfg = &config.TLSConfig{}
	}

	if cfg.CertFile != "" || cfg.KeyFile != "" || cfg.CAFile != "" {
		tlsConfig, err := tls_util.LoadDefaultConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
		if err != nil {
			return nil, err
		}
		log.Debug("load global TLS certificate files OK")
		return tlsConfig, nil
	}

	tlsConfig, err := loadOrGeneratePersistentTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// loadOrGeneratePersistentTLSConfig tries loading an auto-generated CA
// certificate from these locations (in order):
//  1. cert.pem / key.pem in the current working directory (backward compatible)
//  2. auto-ca-cert.pem / auto-ca-key.pem under defaultCertDir() (persisted)
//
// If none is found it generates a new one, persists it to defaultCertDir()
// (best-effort), and returns it.
func loadOrGeneratePersistentTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	log := logger.Default()

	// 1. Try CWD cert.pem / key.pem first (backward compatible).
	cwdCert, cwdErr := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if cwdErr == nil {
		log.Debug("loaded default certificate from current working directory (cert.pem / key.pem)")
		return &tls.Config{Certificates: []tls.Certificate{cwdCert}}, nil
	}

	// 2. Try persisted certificate in defaultCertDir().
	dir := defaultCertDir()
	certFile := filepath.Join(dir, "auto-ca-cert.pem")
	keyFile := filepath.Join(dir, "auto-ca-key.pem")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		log.Debugf("loaded persisted default certificate from %s", dir)
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	log.Debug("generating new default certificate (no persisted certificate found)")

	// 3. Generate a new certificate.
	rawCert, rawKey, err := generateKeyPair(cfg.Validity, cfg.Organization, cfg.CommonName)
	if err != nil {
		return nil, err
	}

	// Best-effort persist to disk. If it fails the in-memory certificate is
	// still usable.
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Warnf("failed to create certificate directory %s: %v", dir, err)
	} else {
		if err := os.WriteFile(certFile, rawCert, 0644); err != nil {
			log.Warnf("failed to persist certificate: %v", err)
		} else if err := os.WriteFile(keyFile, rawKey, 0600); err != nil {
			log.Warnf("failed to persist private key: %v", err)
		} else {
			log.Debugf("persisted default certificate to %s", dir)
		}
	}

	cert, err = tls.X509KeyPair(rawCert, rawKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func generateKeyPair(validity time.Duration, org string, cn string) (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	var priv crypto.PrivateKey
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	if validity <= 0 {
		validity = time.Hour * 24 * 365 // one year
	}
	if org == "" {
		org = "GOST"
	}
	if cn == "" {
		cn = "gost.run"
	}

	validFor := validity
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	template.DNSNames = append(template.DNSNames, cn)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return
}

func publicKey(priv crypto.PrivateKey) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
