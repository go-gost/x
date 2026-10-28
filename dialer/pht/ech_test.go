package pht

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/x/internal/util/ech/echtest"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/stretchr/testify/require"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func echHTTPSServer(t *testing.T, key tls.EncryptedClientHelloKey) (string, <-chan bool) {
	t.Helper()
	accepted := make(chan bool, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			select {
			case accepted <- r.TLS.ECHAccepted:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), accepted
}

func newECHDialer(t *testing.T, doh string, fallback bool) *phtDialer {
	t.Helper()
	d := NewTLSDialer(
		dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop()),
	).(*phtDialer)
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
	addr, accepted := echHTTPSServer(t, key)
	doh := echtest.NewDoHServer(t, list)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	ctx := context.Background()
	conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	defer conn.Close()

	select {
	case v := <-accepted:
		require.True(t, v, "server did not accept ECH")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ECH handshake")
	}
}

func TestDial_ECHFailClosedOnLookupFailure(t *testing.T) {
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	ctx := context.Background()
	_, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	require.Error(t, err)
}
