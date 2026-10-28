package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// newECHConfigDoH starts a DoH server answering HTTPS RRs with list. A nil
// list produces an answer without ECH config, which makes the lookup fail with
// ErrNoECHConfig.
func newECHConfigDoH(t *testing.T, list []byte) string {
	t.Helper()
	srv := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr := &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}},
		}}
		resp.Answer = append(resp.Answer, rr)
		return resp
	})
	return srv.URL + "/dns-query"
}

func newConfig(t *testing.T, doh string, fallback bool) *Config {
	t.Helper()
	c := &Config{
		Enabled:     true,
		DoH:         doh,
		DoHInsecure: true,
		Fallback:    fallback,
	}
	require.NoError(t, c.Init(xlogger.Nop(), nil))
	return c
}

func TestFromMetadata(t *testing.T) {
	md := xmd.NewMetadata(map[string]any{
		"ech":             true,
		"ech.doh":         "https://1.1.1.1/dns-query",
		"ech.timeout":     "2s",
		"ech.ttl":         "10m",
		"ech.fallback":    true,
		"ech.dohInsecure": true,
	})
	c := FromMetadata(md)
	require.True(t, c.Enabled)
	require.Equal(t, "https://1.1.1.1/dns-query", c.DoH)
	require.Equal(t, 2*time.Second, c.Timeout)
	require.Equal(t, 10*time.Minute, c.TTL)
	require.True(t, c.Fallback)
	require.True(t, c.DoHInsecure)
}

func TestConfig_Init_RequiresDoH(t *testing.T) {
	c := &Config{Enabled: true}
	require.Error(t, c.Init(xlogger.Nop(), nil))
}

func TestConfig_Init_RejectsTLS12(t *testing.T) {
	c := &Config{Enabled: true, DoH: "https://1.1.1.1/dns-query"}
	require.Error(t, c.Init(xlogger.Nop(), &tls.Config{MinVersion: tls.VersionTLS12}))

	c = &Config{Enabled: true, DoH: "https://1.1.1.1/dns-query"}
	require.Error(t, c.Init(xlogger.Nop(), &tls.Config{MaxVersion: tls.VersionTLS12}))
}

func TestConfig_Init_Disabled(t *testing.T) {
	var c Config
	require.NoError(t, c.Init(xlogger.Nop(), nil))
	require.False(t, c.Active())
}

func TestConfig_Apply_InjectsConfigList(t *testing.T) {
	list := newTestECHConfigList(t)
	c := newConfig(t, newECHConfigDoH(t, list), false)

	base := &tls.Config{ServerName: "server.example"}
	got, err := c.Apply(context.Background(), base, "server.example")
	require.NoError(t, err)
	require.Equal(t, list, got.EncryptedClientHelloConfigList)
	require.Nil(t, base.EncryptedClientHelloConfigList, "base config must not be mutated")
}

func TestConfig_Apply_InsecureSkipVerifySetsRejectionVerify(t *testing.T) {
	list := newTestECHConfigList(t)
	c := newConfig(t, newECHConfigDoH(t, list), false)

	base := &tls.Config{ServerName: "server.example", InsecureSkipVerify: true}
	got, err := c.Apply(context.Background(), base, "server.example")
	require.NoError(t, err)
	require.NotNil(t, got.EncryptedClientHelloRejectionVerify)
}

func TestConfig_Apply_FallbackOnLookupFailure(t *testing.T) {
	c := newConfig(t, newECHConfigDoH(t, nil), true)

	base := &tls.Config{ServerName: "server.example"}
	got, err := c.Apply(context.Background(), base, "server.example")
	require.NoError(t, err)
	require.Empty(t, got.EncryptedClientHelloConfigList)
}

func TestConfig_Apply_FailClosedOnLookupFailure(t *testing.T) {
	c := newConfig(t, newECHConfigDoH(t, nil), false)

	_, err := c.Apply(context.Background(), nil, "server.example")
	require.Error(t, err)
}

func TestConfig_Apply_RequiresServerName(t *testing.T) {
	list := newTestECHConfigList(t)
	c := newConfig(t, newECHConfigDoH(t, list), true)

	_, err := c.Apply(context.Background(), nil, "")
	require.ErrorContains(t, err, "server name")
}

func TestConfig_Apply_DisabledReturnsBase(t *testing.T) {
	var c Config
	base := &tls.Config{ServerName: "server.example"}
	got, err := c.Apply(context.Background(), base, "server.example")
	require.NoError(t, err)
	require.Same(t, base, got)
}

func TestConfig_OnRejection_RetryConfigs(t *testing.T) {
	oldList := newTestECHConfigList(t)
	newList := newTestECHConfigList(t)
	c := newConfig(t, newECHConfigDoH(t, oldList), false)

	_, err := c.Apply(context.Background(), nil, "server.example")
	require.NoError(t, err)

	rerr := c.OnRejection(&tls.ECHRejectionError{RetryConfigList: newList}, "server.example")
	require.Error(t, rerr)
	var r interface{ RetryableHandshake() bool }
	require.ErrorAs(t, rerr, &r)
	require.True(t, r.RetryableHandshake())

	got, err := c.Apply(context.Background(), nil, "server.example")
	require.NoError(t, err)
	require.Equal(t, newList, got.EncryptedClientHelloConfigList)
}

func TestConfig_OnRejection_FallbackDisables(t *testing.T) {
	list := newTestECHConfigList(t)
	c := newConfig(t, newECHConfigDoH(t, list), true)

	_, err := c.Apply(context.Background(), nil, "server.example")
	require.NoError(t, err)

	rerr := c.OnRejection(&tls.ECHRejectionError{}, "server.example")
	require.Error(t, rerr)

	got, err := c.Apply(context.Background(), nil, "server.example")
	require.NoError(t, err)
	require.Empty(t, got.EncryptedClientHelloConfigList)
}

func TestConfig_OnRejection_NotARejection(t *testing.T) {
	list := newTestECHConfigList(t)
	c := newConfig(t, newECHConfigDoH(t, list), true)
	require.NoError(t, c.OnRejection(errors.New("boom"), "server.example"))
}

func TestConfig_OnDialError_RefreshAndRetryable(t *testing.T) {
	list := newTestECHConfigList(t)
	var count atomic.Int32
	doh := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		count.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}},
		}})
		return resp
	})
	c := newConfig(t, doh.URL+"/dns-query", false)

	_, err := c.Apply(context.Background(), nil, "server.example")
	require.NoError(t, err)
	require.EqualValues(t, 1, count.Load())

	derr := c.OnDialError(context.Background(), errors.New("handshake failed"), "server.example")
	require.Error(t, derr)
	var r interface{ RetryableHandshake() bool }
	require.ErrorAs(t, derr, &r)

	_, err = c.Apply(context.Background(), nil, "server.example")
	require.NoError(t, err)
	require.EqualValues(t, 2, count.Load(), "cached entry must be refreshed")
}

func TestConfig_OnDialError_Inactive(t *testing.T) {
	var c Config
	require.NoError(t, c.OnDialError(context.Background(), errors.New("x"), "server.example"))
}
