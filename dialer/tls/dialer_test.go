package tls

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	xmd "github.com/go-gost/x/metadata"
	"github.com/stretchr/testify/require"
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
	require.True(t, d.md.ech)
	require.Equal(t, "https://1.1.1.1/dns-query", d.md.echDoH)
	require.Equal(t, 2*time.Second, d.md.echTimeout)
	require.Equal(t, 10*time.Minute, d.md.echTTL)
	require.True(t, d.md.echFallback)
	require.True(t, d.md.echDoHInsecure)
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
	require.Nil(t, d.ech)
}
