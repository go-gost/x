package h2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

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
			accepted <- r.TLS.ECHAccepted
		} else {
			accepted <- false
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), accepted
}

func newECHDialer(t *testing.T, doh string, fallback bool) *h2Dialer {
	t.Helper()
	d := NewTLSDialer(
		dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop()),
	).(*h2Dialer)
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
	require.True(t, <-accepted, "server did not accept ECH")
}

func TestDial_ECHFailClosedOnLookupFailure(t *testing.T) {
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	ctx := context.Background()
	_, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	require.Error(t, err)
}

func TestDial_ECHFallbackOnLookupFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()

	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", true)
	ctx := context.Background()
	conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	if err == nil {
		conn.Close()
	}
	var r interface{ RetryableHandshake() bool }
	require.False(t, err != nil && asRetryable(err, &r))
}

func asRetryable(err error, target *interface{ RetryableHandshake() bool }) bool {
	for err != nil {
		if r, ok := err.(interface{ RetryableHandshake() bool }); ok {
			*target = r
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
