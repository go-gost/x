// Package echtest provides helpers for exercising ECH support in tests.
//
// It is imported from _test.go files only, so it never ships in the binary.
package echtest

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/cryptobyte"
)

// SelfSignedCert returns a self-signed certificate valid for 127.0.0.1.
func SelfSignedCert(t testing.TB) tls.Certificate {
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

// NewConfigList returns a serialized ECHConfigList and the matching server key.
func NewConfigList(t testing.TB) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()

	marshal := func() []byte {
		b := cryptobyte.NewBuilder(nil)
		b.AddUint16(0xfe0d) // ECHConfig version
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1)     // config_id
			b.AddUint16(0x20) // DHKEM(X25519, HKDF-SHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pub) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x0001) // HKDF-SHA256
				b.AddUint16(0x0001) // AES-128-GCM
			})
			b.AddUint8(0) // maximum_name_length
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte("public.example"))
			})
			b.AddUint16(0) // extensions
		})
		return b.BytesOrPanic()
	}

	echConfig := marshal()
	list := cryptobyte.NewBuilder(nil)
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echConfig) })

	return list.BytesOrPanic(), tls.EncryptedClientHelloKey{
		Config:     echConfig,
		PrivateKey: priv.Bytes(),
	}
}

// NewDoHServer starts a DoH server answering HTTPS RRs with list. A nil list
// yields an answer without ECH config, so lookups fail with "no ECH config".
func NewDoHServer(t testing.TB, list []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		resp.Answer = append(resp.Answer, &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}},
		}})
		buf, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// NewTLSServer starts a TLS listener and discards everything it receives.
func NewTLSServer(t testing.TB, cfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, cfg)
	t.Cleanup(func() { tlsLn.Close() })
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				io.Copy(io.Discard, conn)
				conn.Close()
			}(c)
		}
	}()
	return tlsLn.Addr().String()
}

// NewECHServer starts a TLS server that accepts ECH with a fresh config list
// and returns its address together with the matching ECHConfigList.
func NewECHServer(t testing.TB) (string, []byte) {
	t.Helper()
	list, key := NewConfigList(t)
	addr := NewTLSServer(t, &tls.Config{
		Certificates:             []tls.Certificate{SelfSignedCert(t)},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
	})
	return addr, list
}

// NewPlainServer starts a TLS server without ECH support.
func NewPlainServer(t testing.TB) string {
	t.Helper()
	return NewTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{SelfSignedCert(t)},
	})
}
