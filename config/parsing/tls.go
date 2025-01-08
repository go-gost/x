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
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	tls_util "github.com/go-gost/x/internal/util/tls"
)

var (
	defaultTLSConfig atomic.Value
)

func DefaultTLSConfig() *tls.Config {
	v, _ := defaultTLSConfig.Load().(*tls.Config)
	return v
}

func SetDefaultTLSConfig(cfg *tls.Config) {
	defaultTLSConfig.Store(cfg)
}

func BuildDefaultTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	log := logger.Default()

	if cfg == nil {
		cfg = &config.TLSConfig{
			CertFile: "cert.pem",
			KeyFile:  "key.pem",
			CAFile:   "ca.pem",
		}
	}

	tlsConfig, err := tls_util.LoadDefaultConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		// generate random self-signed certificate.
		cert, err := genCertificate(cfg.Validity, cfg.Organization, cfg.CommonName)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		log.Debug("load global TLS certificate files failed, use random generated certificate")
	} else {
		log.Debug("load global TLS certificate files OK")
	}

	return tlsConfig, nil
}

func genCertificate(validity time.Duration, org string, cn string) (cert tls.Certificate, err error) {
	rawCert, rawKey, err := generateKeyPair(validity, org, cn)
	if err != nil {
		return
	}
	return tls.X509KeyPair(rawCert, rawKey)
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
