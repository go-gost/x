package tls

import (
	"context"
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

	"github.com/go-gost/core/dialer"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestParseMetadata_ECH(t *testing.T) {
	d := NewDialer().(*tlsDialer)
	md := xmd.NewMetadata(map[string]any{
		"ech":             true,
		"ech.doh":         "https://1.1.1.1/dns-query",
		"ech.timeout":     "2s",
		"ech.ttl":         "10m",
		"ech.fallback":    true,
		"ech.dohInsecure": true,
	})
	require.NoError(t, d.parseMetadata(md))
	require.True(t, d.md.ech.Enabled)
	require.Equal(t, "https://1.1.1.1/dns-query", d.md.ech.DoH)
	require.Equal(t, 2*time.Second, d.md.ech.Timeout)
	require.Equal(t, 10*time.Minute, d.md.ech.TTL)
	require.True(t, d.md.ech.Fallback)
	require.True(t, d.md.ech.DoHInsecure)
}

func TestInit_ECHRequiresDoH(t *testing.T) {
	d := NewDialer().(*tlsDialer)
	err := d.Init(xmd.NewMetadata(map[string]any{"ech": true}))
	require.Error(t, err)
}

func TestInit_ECHRejectsTLS12(t *testing.T) {
	d := NewDialer(dialer.TLSConfigOption(&tls.Config{MinVersion: tls.VersionTLS12})).(*tlsDialer)
	err := d.Init(xmd.NewMetadata(map[string]any{
		"ech": true, "ech.doh": "https://1.1.1.1/dns-query",
	}))
	require.Error(t, err)
}

func TestInit_ECHDisabled(t *testing.T) {
	d := NewDialer().(*tlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(nil)))
	require.False(t, d.md.ech.Active())
}

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
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

func newTLSListener(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
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

func newDoHServer(t *testing.T, fn func(req *dns.Msg) *dns.Msg) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		resp := fn(&req)
		if resp == nil {
			w.WriteHeader(500)
			return
		}
		buf, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestECHConfig(t *testing.T) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey().Bytes()

	marshalECHConfig := func(version uint16, id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint16(version)
		builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(id)
			b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pubKey) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x0001) // HKDF-SHA256
				b.AddUint16(0x0001) // AES-128-GCM
			})
			b.AddUint8(maxNameLen)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
			b.AddUint16(0) // extensions
		})
		return builder.BytesOrPanic()
	}

	echConfig := marshalECHConfig(0xfe0d, 123, pub, "server.example", 32)

	listBuilder := cryptobyte.NewBuilder(nil)
	listBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echConfig) })
	echConfigList := listBuilder.BytesOrPanic()

	key := tls.EncryptedClientHelloKey{Config: echConfig, PrivateKey: priv.Bytes(), SendAsRetry: true}
	return echConfigList, key
}

func TestHandshake_ECHRejectionRetryable(t *testing.T) {
	list, _ := newTestECHConfig(t)
	srv := newTLSListener(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	doh := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr := &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}},
		}}
		resp.Answer = append(resp.Answer, rr)
		return resp
	})
	d := NewDialer(dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop())).(*tlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech": true, "ech.doh": doh.URL + "/dns-query", "ech.dohInsecure": true, "ech.fallback": true,
	})))
	conn, err := d.Dial(context.Background(), srv, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn)
	var rej *tls.ECHRejectionError
	require.ErrorAs(t, err, &rej)
	r, ok := err.(interface{ RetryableHandshake() bool })
	require.True(t, ok)
	require.True(t, r.RetryableHandshake())
	// 第二次握手：ECH 已被禁用，走明文
	conn2, err := d.Dial(context.Background(), srv, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn2)
	require.NoError(t, err)
}

func TestHandshake_ECHFallbackOnLookupFailure(t *testing.T) {
	srv := newTLSListener(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	doh := newDoHServer(t, func(req *dns.Msg) *dns.Msg { return nil })
	d := NewDialer(dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop())).(*tlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech": true, "ech.doh": doh.URL + "/dns-query", "ech.dohInsecure": true, "ech.fallback": true,
	})))
	conn, err := d.Dial(context.Background(), srv, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn)
	require.NoError(t, err)
}

func TestHandshake_ECHFailClosedOnLookupFailure(t *testing.T) {
	srv := newTLSListener(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	doh := newDoHServer(t, func(req *dns.Msg) *dns.Msg { return nil })
	d := NewDialer(dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop())).(*tlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech": true, "ech.doh": doh.URL + "/dns-query", "ech.dohInsecure": true,
	})))
	conn, err := d.Dial(context.Background(), srv, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn)
	require.Error(t, err)
}

func TestHandshake_ECHMissingServerName(t *testing.T) {
	d := NewDialer(dialer.TLSConfigOption(&tls.Config{InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop())).(*tlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech": true, "ech.doh": "https://1.1.1.1/dns-query", "ech.dohInsecure": true,
	})))
	conn, _ := net.Dial("tcp", "127.0.0.1:1")
	if conn != nil {
		defer conn.Close()
	}
	_, err := d.Handshake(context.Background(), conn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "server name")
}

func TestHandshake_ECHSuccess(t *testing.T) {
	list, key := newTestECHConfig(t)
	srv := newTLSListener(t, &tls.Config{
		Certificates:             []tls.Certificate{selfSignedCert(t)},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
	})
	doh := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr := &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}},
		}}
		resp.Answer = append(resp.Answer, rr)
		return resp
	})
	d := NewDialer(dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop())).(*tlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech": true, "ech.doh": doh.URL + "/dns-query", "ech.dohInsecure": true, "ech.fallback": true,
	})))
	conn, err := d.Dial(context.Background(), srv, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	tconn, err := d.Handshake(context.Background(), conn)
	require.NoError(t, err)
	require.True(t, tconn.(*tls.Conn).ConnectionState().ECHAccepted)
}
