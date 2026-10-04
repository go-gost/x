package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/listener"
	mtls_listener "github.com/go-gost/x/listener/mtls"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// echoServer serves mtls on a local port and echoes every stream.
func echoServer(t *testing.T) string {
	t.Helper()
	ln := mtls_listener.NewListener(
		listener.AddrOption("127.0.0.1:0"),
		listener.TLSConfigOption(&tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}),
		listener.LoggerOption(xlogger.Nop()),
	)
	if err := ln.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Concurrent requests that find no live session each dial a conn of their
// own, and a Dial that finds a session still waiting for its handshake
// replaces it. Both handshakes must still end on one usable session,
// whichever runs first; they used to fail with "unrecognized connection",
// or on a conn the later Dial had closed.
func TestHandshakeAfterAnotherDial(t *testing.T) {
	for _, first := range []string{"earlier", "later"} {
		t.Run(first+" conn first", func(t *testing.T) {
			addr := echoServer(t)
			d := NewDialer(
				dialer.TLSConfigOption(&tls.Config{InsecureSkipVerify: true}),
				dialer.LoggerOption(xlogger.Nop()),
			)
			if err := d.Init(xmd.NewMetadata(nil)); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()

			earlier, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
			if err != nil {
				t.Fatal(err)
			}
			later, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
			if err != nil {
				t.Fatal(err)
			}
			conns := []net.Conn{earlier, later}
			if first == "later" {
				conns = []net.Conn{later, earlier}
			}
			for i, conn := range conns {
				cc, err := d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
				if err != nil {
					t.Fatalf("handshake %d: %v", i+1, err)
				}
				if _, err := cc.Write([]byte("ping")); err != nil {
					t.Fatalf("handshake %d: write: %v", i+1, err)
				}
				if _, err := io.ReadFull(cc, make([]byte, 4)); err != nil {
					t.Fatalf("handshake %d: read: %v", i+1, err)
				}
				cc.Close()
			}
		})
	}
}
