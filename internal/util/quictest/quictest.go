// Package quictest provides an in-process QUIC peer for tests: a TLS
// configuration for a self-signed server, and helpers to listen and dial on
// the loopback interface.
//
// A QUIC stream is created implicitly by sending data on it, so a client
// that opens a stream must write before the server's AcceptStream returns.
package quictest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// SelfSignedTLS returns a server and a client TLS configuration for a
// self-signed certificate valid for 127.0.0.1.
func SelfSignedTLS() (server, client *tls.Config, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"GOST"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"gost"},
	}, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"gost"},
	}, nil
}

// Listen starts a QUIC listener on a loopback UDP socket and returns it
// together with the address it listens on.
func Listen(tlsConf *tls.Config) (ln *quic.Listener, addr net.Addr, err error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, err
	}
	ln, err = quic.Listen(pc, tlsConf, &quic.Config{})
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	return ln, pc.LocalAddr(), nil
}

// Dial connects to a QUIC listener on a loopback UDP socket.
func Dial(ctx context.Context, addr net.Addr, tlsConf *tls.Config) (conn *quic.Conn, err error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	conn, err = quic.Dial(ctx, pc, addr, tlsConf, &quic.Config{})
	if err != nil {
		pc.Close()
		return nil, err
	}
	return conn, nil
}

// ErrNoStream is returned when a peer closes its stream without sending
// anything, so that AcceptStream never returns.
var ErrNoStream = errors.New("no stream")
