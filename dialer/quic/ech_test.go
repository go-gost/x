package quic

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/x/internal/util/ech/echtest"
	"github.com/go-gost/x/internal/util/quictest"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/stretchr/testify/require"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "udp" && addr == "" {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func echQUICServer(t *testing.T, key tls.EncryptedClientHelloKey) (string, <-chan bool) {
	t.Helper()
	serverTLS, _, err := quictest.SelfSignedTLS()
	require.NoError(t, err)
	serverTLS.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key}
	serverTLS.NextProtos = []string{"gost"}

	ln, addr, err := quictest.Listen(serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		accepted <- conn.ConnectionState().TLS.ECHAccepted
		stream, err := conn.AcceptStream(context.Background())
		if err == nil {
			defer stream.Close()
			buf := make([]byte, 1)
			stream.Read(buf)
		}
	}()
	return addr.String(), accepted
}

func newECHDialer(t *testing.T, doh string, fallback bool) *quicDialer {
	t.Helper()
	_, clientTLS, err := quictest.SelfSignedTLS()
	require.NoError(t, err)
	clientTLS.ServerName = "server.example"
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"gost"}

	d := NewDialer(
		dialer.TLSConfigOption(clientTLS),
		dialer.LoggerOption(xlogger.Nop()),
	).(*quicDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech":             true,
		"ech.doh":         doh,
		"ech.dohInsecure": true,
		"ech.fallback":    fallback,
	})))
	return d
}

func TestDial_ECHSuccess(t *testing.T) {
	list, key := echtest.NewConfigList(t)
	addr, accepted := echQUICServer(t, key)
	doh := echtest.NewDoHServer(t, list)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	ctx := context.Background()
	conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	defer func() { conn.Close() }()

	select {
	case v := <-accepted:
		require.True(t, v, "server did not accept ECH")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ECH handshake")
	}
}

func TestDial_ECHFailClosedOnLookupFailure(t *testing.T) {
	serverTLS, clientTLS, err := quictest.SelfSignedTLS()
	require.NoError(t, err)
	clientTLS.ServerName = "server.example"
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"gost"}

	ln, addr, err := quictest.Listen(serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(context.Background())
		if err == nil {
			defer stream.Close()
		}
	}()

	doh := echtest.NewDoHServer(t, nil)
	d := NewDialer(
		dialer.TLSConfigOption(clientTLS),
		dialer.LoggerOption(xlogger.Nop()),
	).(*quicDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech":             true,
		"ech.doh":         doh.URL + "/dns-query",
		"ech.dohInsecure": true,
		"ech.fallback":    false,
	})))
	_, err = d.Dial(context.Background(), addr.String(), dialer.NetDialerDialOption(netDialer{}))
	require.Error(t, err)
}
