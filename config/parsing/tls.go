package parsing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
)

var (
	defaultTLSConfig *tls.Config
)

func BuildDefaultTLSConfig(cfg *config.TLSConfig) {
	log := logger.Default()

	if cfg == nil {
		cfg = &config.TLSConfig{
			CertFile: "cert.pem",
			KeyFile:  "key.pem",
		}
	}

	tlsConfig, err := loadConfig(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		// generate random self-signed certificate.
		cert, err := genCertificate(cfg.Validity, cfg.Organization, cfg.CommonName)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		log.Warn("load global TLS certificate files failed, use random generated certificate")
	} else {
		log.Info("load global TLS certificate files OK")
	}
	defaultTLSConfig = tlsConfig
}

func loadConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return cfg, nil
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

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, cn)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
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
