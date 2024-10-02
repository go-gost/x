package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/patrickmn/go-cache"
)

const (
	VersionTLS10 = "VersionTLS10"
	VersionTLS11 = "VersionTLS11"
	VersionTLS12 = "VersionTLS12"
	VersionTLS13 = "VersionTLS13"
)

// Cipher suites from https://pkg.go.dev/crypto/tls#pkg-constants
const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      = "TLS_RSA_WITH_RC4_128_SHA"
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	TLS_RSA_WITH_AES_128_CBC_SHA                  = "TLS_RSA_WITH_AES_128_CBC_SHA"
	TLS_RSA_WITH_AES_256_CBC_SHA                  = "TLS_RSA_WITH_AES_256_CBC_SHA"
	TLS_RSA_WITH_AES_128_CBC_SHA256               = "TLS_RSA_WITH_AES_128_CBC_SHA256"
	TLS_RSA_WITH_AES_128_GCM_SHA256               = "TLS_RSA_WITH_AES_128_GCM_SHA256"
	TLS_RSA_WITH_AES_256_GCM_SHA384               = "TLS_RSA_WITH_AES_256_GCM_SHA384"
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       = "TLS_AES_128_GCM_SHA256"
	TLS_AES_256_GCM_SHA384       = "TLS_AES_256_GCM_SHA384"
	TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV"
)

var (
	cipherSuites = map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                      TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

		tls.TLS_AES_128_GCM_SHA256:       TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384:       TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256: TLS_CHACHA20_POLY1305_SHA256,
	}

	versions = map[uint16]string{
		tls.VersionSSL30: "sslv3",
		tls.VersionTLS10: "tls1.0",
		tls.VersionTLS11: "tls1.1",
		tls.VersionTLS12: "tls1.2",
		tls.VersionTLS13: "tls1.3",
	}
)

type CipherSuite uint16

func (cs CipherSuite) String() string {
	if v, ok := cipherSuites[uint16(cs)]; ok {
		return v
	}
	return strconv.Itoa(int(cs))
}

type Version uint16

func (ver Version) String() string {
	if v, ok := versions[uint16(ver)]; ok {
		return v
	}
	return strconv.Itoa(int(ver))
}

// LoadDefaultConfig loads the certificate from cert & key files and optional CA file.
func LoadDefaultConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	pool, err := loadCA(caFile)
	if err != nil {
		logger.Default().Debugf("load default CA(%s): %v", caFile, err)
	}
	if pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

// LoadServerConfig loads the certificate from cert & key files and client CA file.
func LoadServerConfig(config *config.TLSConfig) (*tls.Config, error) {
	if config.CertFile == "" && config.KeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	pool, err := loadCA(config.CAFile)
	if err != nil {
		return nil, err
	}
	if pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	SetTLSOptions(cfg, config.Options)

	return cfg, nil
}

// LoadClientConfig loads the certificate from cert & key files and CA file.
func LoadClientConfig(config *config.TLSConfig) (*tls.Config, error) {
	var cfg *tls.Config

	if config.CertFile == "" && config.KeyFile == "" {
		cfg = &tls.Config{}
	} else {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, err
		}

		cfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	rootCAs, err := loadCA(config.CAFile)
	if err != nil {
		return nil, err
	}

	cfg.RootCAs = rootCAs
	cfg.ServerName = config.ServerName
	cfg.InsecureSkipVerify = !config.Secure

	if config.Options != nil {
		SetTLSOptions(cfg, config.Options)
	}

	// If the root ca is given, but skip verify, we verify the certificate manually.
	if cfg.RootCAs != nil && !config.Secure {
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         cfg.RootCAs,
				CurrentTime:   time.Now(),
				DNSName:       "",
				Intermediates: x509.NewCertPool(),
			}

			certs := state.PeerCertificates
			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)
			return err
		}
	}

	return cfg, nil
}

func SetTLSOptions(cfg *tls.Config, opts *config.TLSOptions) {
	if cfg == nil || opts == nil {
		return
	}

	switch strings.ToLower(opts.MinVersion) {
	case strings.ToLower(VersionTLS10):
		cfg.MinVersion = tls.VersionTLS10
	case strings.ToLower(VersionTLS11):
		cfg.MinVersion = tls.VersionTLS11
	case strings.ToLower(VersionTLS12):
		cfg.MinVersion = tls.VersionTLS12
	case strings.ToLower(VersionTLS13):
		cfg.MinVersion = tls.VersionTLS13
	}
	switch strings.ToLower(opts.MaxVersion) {
	case strings.ToLower(VersionTLS10):
		cfg.MaxVersion = tls.VersionTLS10
	case strings.ToLower(VersionTLS11):
		cfg.MaxVersion = tls.VersionTLS11
	case strings.ToLower(VersionTLS12):
		cfg.MaxVersion = tls.VersionTLS12
	case strings.ToLower(VersionTLS13):
		cfg.MaxVersion = tls.VersionTLS13
	}
	for _, v := range opts.CipherSuites {
		switch strings.ToUpper(v) {
		case TLS_RSA_WITH_RC4_128_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_RC4_128_SHA)
		case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
		case TLS_RSA_WITH_AES_128_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
		case TLS_RSA_WITH_AES_256_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_256_CBC_SHA)
		case TLS_RSA_WITH_AES_128_CBC_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA256)
		case TLS_RSA_WITH_AES_128_GCM_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
		case TLS_RSA_WITH_AES_256_GCM_SHA384:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_256_GCM_SHA384)
		case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
		case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
		case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
		case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)
		case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
		case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
		case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
		case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
		case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
		case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
		case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
		case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
		}
	}

	cfg.NextProtos = opts.ALPN
}

func loadCA(caFile string) (cp *x509.CertPool, err error) {
	if caFile == "" {
		return
	}
	cp = x509.NewCertPool()
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !cp.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("loadCA %s: AppendCertsFromPEM failed", caFile)
	}
	return
}

// Wrap a net.Conn into a client tls connection, performing any
// additional verification as needed.
//
// As of go 1.3, crypto/tls only supports either doing no certificate
// verification, or doing full verification including of the peer's
// DNS name. For consul, we want to validate that the certificate is
// signed by a known CA, but because consul doesn't use DNS names for
// node names, we don't verify the certificate DNS names. Since go 1.3
// no longer supports this mode of operation, we have to do it
// manually.
//
// This code is taken from consul:
// https://github.com/hashicorp/consul/blob/master/tlsutil/config.go
func WrapTLSClient(conn net.Conn, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	var err error
	var tlsConn *tls.Conn

	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
	}

	tlsConn = tls.Client(conn, tlsConfig)

	// Otherwise perform handshake, but don't verify the domain
	//
	// The following is lightly-modified from the doFullHandshake
	// method in https://golang.org/src/crypto/tls/handshake_client.go
	if err = tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// We can do this in `tls.Config.VerifyConnection`, which effective for
	// other TLS protocols such as WebSocket. See `route.go:parseChainNode`
	/*
		// If crypto/tls is doing verification, there's no need to do our own.
		if tlsConfig.InsecureSkipVerify == false {
			return tlsConn, nil
		}

		// Similarly if we use host's CA, we can do full handshake
		if tlsConfig.RootCAs == nil {
			return tlsConn, nil
		}

		opts := x509.VerifyOptions{
			Roots:         tlsConfig.RootCAs,
			CurrentTime:   time.Now(),
			DNSName:       "",
			Intermediates: x509.NewCertPool(),
		}

		certs := tlsConn.ConnectionState().PeerCertificates
		for i, cert := range certs {
			if i == 0 {
				continue
			}
			opts.Intermediates.AddCert(cert)
		}

		_, err = certs[0].Verify(opts)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
	*/

	return tlsConn, err
}

var (
	ErrCertNotFound = errors.New("certificate not found")
)

type CertPool interface {
	Get(serverName string) (*x509.Certificate, error)
	Put(serverName string, cert *x509.Certificate)
}

type memoryCertPool struct {
	cache *cache.Cache
}

func NewMemoryCertPool() CertPool {
	return &memoryCertPool{
		cache: cache.New(24*7*time.Hour, 1*time.Hour),
	}
}

func (p *memoryCertPool) Get(serverName string) (*x509.Certificate, error) {
	v, ok := p.cache.Get(serverName)
	if !ok {
		return nil, ErrCertNotFound
	}
	return v.(*x509.Certificate), nil
}

func (p *memoryCertPool) Put(serverName string, cert *x509.Certificate) {
	p.cache.Set(serverName, cert, cache.DefaultExpiration)
}

func GenerateCertificate(serverName string, validity time.Duration, caCert *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, error) {
	if host, _, _ := net.SplitHostPort(serverName); host != "" {
		serverName = host
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			Organization: []string{"GOST"},
		},
		NotBefore:          time.Now().Add(-validity),
		NotAfter:           time.Now().Add(validity),
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.Subject.CommonName = serverName
		tmpl.DNSNames = []string{serverName}
	}

	pk, ok := caKey.(privateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pk.Public(), caKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(raw)
}

// https://pkg.go.dev/crypto#PrivateKey
type privateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}
