package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
)

const (
	VersionTLS10 = "VersionTLS10"
	VersionTLS11 = "VersionTLS11"
	VersionTLS12 = "VersionTLS12"
	VersionTLS13 = "VersionTLS13"
)

const (
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
)

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
		switch strings.ToLower(v) {
		case strings.ToLower(TLS_RSA_WITH_RC4_128_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_RC4_128_SHA)
		case strings.ToLower(TLS_RSA_WITH_3DES_EDE_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
		case strings.ToLower(TLS_RSA_WITH_AES_128_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
		case strings.ToLower(TLS_RSA_WITH_AES_256_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_256_CBC_SHA)
		case strings.ToLower(TLS_RSA_WITH_AES_128_CBC_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA256)
		case strings.ToLower(TLS_RSA_WITH_AES_128_GCM_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
		case strings.ToLower(TLS_RSA_WITH_AES_256_GCM_SHA384):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_RSA_WITH_AES_256_GCM_SHA384)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_RC4_128_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		case strings.ToLower(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
		case strings.ToLower(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256):
			cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
		}
	}
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
		return nil, errors.New("AppendCertsFromPEM failed")
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
