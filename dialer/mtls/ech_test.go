package mtls

import (
	"context"
	"crypto/tls"
	"io"
	"testing"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/x/internal/util/ech/echtest"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/stretchr/testify/require"
)

// echListener starts a TLS listener with ECH keys and reports, for the first
// accepted connection, whether ECH was accepted.
func echListener(t *testing.T, key tls.EncryptedClientHelloKey) (string, <-chan bool) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:             []tls.Certificate{selfSignedCert(t)},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			accepted <- false
			return
		}
		accepted <- tc.ConnectionState().ECHAccepted
		io.Copy(io.Discard, tc)
	}()
	return ln.Addr().String(), accepted
}

func newECHDialer(t *testing.T, doh string, fallback bool) *mtlsDialer {
	t.Helper()
	d := NewDialer(
		dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop()),
	).(*mtlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech":             true,
		"ech.doh":         doh,
		"ech.dohInsecure": true,
		"ech.fallback":    fallback,
	})))
	return d
}

func TestHandshake_ECHSuccess(t *testing.T) {
	list, key := echtest.NewConfigList(t)
	addr, accepted := echListener(t, key)
	doh := echtest.NewDoHServer(t, list)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	cc, err := d.Handshake(context.Background(), conn, dialer.AddrHandshakeOption(addr))
	require.NoError(t, err)
	defer cc.Close()
	require.True(t, <-accepted, "server did not accept ECH")
}

func TestHandshake_ECHRejectionRetryable(t *testing.T) {
	list, _ := echtest.NewConfigList(t)
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, list)

	d := newECHDialer(t, doh.URL+"/dns-query", true)
	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn, dialer.AddrHandshakeOption(addr))
	require.Error(t, err)
	var r interface{ RetryableHandshake() bool }
	require.ErrorAs(t, err, &r)
	require.True(t, r.RetryableHandshake())
}

func TestHandshake_ECHFailClosedOnLookupFailure(t *testing.T) {
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn, dialer.AddrHandshakeOption(addr))
	require.Error(t, err)
}

func TestHandshake_ECHFallbackOnLookupFailure(t *testing.T) {
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", true)
	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	cc, err := d.Handshake(context.Background(), conn, dialer.AddrHandshakeOption(addr))
	require.NoError(t, err)
	cc.Close()
}
