package utls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/x/internal/util/ech/echtest"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func newECHDialer(t *testing.T, doh string, fallback bool, fingerprint string) *utlsDialer {
	t.Helper()
	d := NewDialer(
		dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop()),
	).(*utlsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech":             true,
		"ech.doh":         doh,
		"ech.dohInsecure": true,
		"ech.fallback":    fallback,
		"fingerprint":     fingerprint,
	})))
	return d
}

func TestHandshake_ECHSuccess(t *testing.T) {
	addr, list := echtest.NewECHServer(t)
	doh := echtest.NewDoHServer(t, list)

	for _, fingerprint := range []string{"", "chrome"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			d := newECHDialer(t, doh.URL+"/dns-query", false, fingerprint)

			conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
			require.NoError(t, err)
			c, err := d.Handshake(context.Background(), conn)
			require.NoError(t, err)
			defer c.Close()

			switch cc := c.(type) {
			case *utls.UConn:
				require.True(t, cc.ConnectionState().ECHAccepted)
			case *tls.Conn:
				require.True(t, cc.ConnectionState().ECHAccepted)
			default:
				t.Fatalf("unexpected conn type %T", c)
			}
		})
	}
}

func TestHandshake_ECHRejectionRetryable(t *testing.T) {
	list, _ := echtest.NewConfigList(t)
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, list)

	d := newECHDialer(t, doh.URL+"/dns-query", true, "")

	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn)
	require.Error(t, err)
	var r interface{ RetryableHandshake() bool }
	require.ErrorAs(t, err, &r)
	require.True(t, r.RetryableHandshake())
}

func TestHandshake_ECHFailClosedOnLookupFailure(t *testing.T) {
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", false, "")
	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	_, err = d.Handshake(context.Background(), conn)
	require.Error(t, err)
}

func TestHandshake_ECHFallbackOnLookupFailure(t *testing.T) {
	addr := echtest.NewPlainServer(t)
	doh := echtest.NewDoHServer(t, nil)

	d := newECHDialer(t, doh.URL+"/dns-query", true, "")
	conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	c, err := d.Handshake(context.Background(), conn)
	require.NoError(t, err)
	c.Close()
}
