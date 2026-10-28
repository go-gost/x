package mws

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/x/internal/util/ech/echtest"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func echWebsocketServer(t *testing.T, key tls.EncryptedClientHelloKey) (string, <-chan bool) {
	t.Helper()
	accepted := make(chan bool, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted <- r.TLS != nil && r.TLS.ECHAccepted
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	srv.TLS = &tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), accepted
}

func newECHDialer(t *testing.T, doh string, fallback bool) *mwsDialer {
	t.Helper()
	d := NewTLSDialer(
		dialer.TLSConfigOption(&tls.Config{ServerName: "server.example", InsecureSkipVerify: true}),
		dialer.LoggerOption(xlogger.Nop()),
	).(*mwsDialer)
	require.NoError(t, d.Init(xmd.NewMetadata(map[string]any{
		"ech":              true,
		"ech.doh":          doh,
		"ech.dohInsecure":  true,
		"ech.fallback":     fallback,
		"handshakeTimeout": "1s",
	})))
	return d
}

func TestHandshake_ECHSuccess(t *testing.T) {
	list, key := echtest.NewConfigList(t)
	addr, accepted := echWebsocketServer(t, key)
	doh := echtest.NewDoHServer(t, list)

	d := newECHDialer(t, doh.URL+"/dns-query", false)
	ctx := context.Background()
	conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	require.NoError(t, err)
	cc, err := d.Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
	require.NoError(t, err)
	defer cc.Close()
	require.True(t, <-accepted, "server did not accept ECH")
}
