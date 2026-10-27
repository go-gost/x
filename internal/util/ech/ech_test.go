package ech

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func newDoHServer(t *testing.T, answer func(*dns.Msg) *dns.Msg) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		resp := answer(&req)
		buf, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestECHConfigList(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey().Bytes()
	var cfg bytes.Buffer
	cfg.WriteByte(1)
	binary.Write(&cfg, binary.BigEndian, uint16(0x0020))
	binary.Write(&cfg, binary.BigEndian, uint16(len(pub)))
	cfg.Write(pub)
	binary.Write(&cfg, binary.BigEndian, uint16(4))
	binary.Write(&cfg, binary.BigEndian, uint16(0x0001))
	binary.Write(&cfg, binary.BigEndian, uint16(0x0001))
	cfg.WriteByte(0)
	const publicName = "public.example"
	cfg.WriteByte(byte(len(publicName)))
	cfg.Write([]byte(publicName))
	binary.Write(&cfg, binary.BigEndian, uint16(0))
	var list bytes.Buffer
	binary.Write(&list, binary.BigEndian, uint16(cfg.Len()))
	list.Write(cfg.Bytes())
	return list.Bytes()
}

func TestConfigList_FetchAndCache(t *testing.T) {
	list := newTestECHConfigList(t)
	var count atomic.Int32
	srv := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		count.Add(1)
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
	c, err := NewClient(srv.URL+"/dns-query", TLSConfigOption(&tls.Config{InsecureSkipVerify: true}))
	require.NoError(t, err)
	got, err := c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, list, got)
	got2, err := c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, list, got2)
	require.Equal(t, int32(1), count.Load())
}

func TestConfigList_NoECH(t *testing.T) {
	var count atomic.Int32
	srv := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		count.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr := &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1,
			Target:   ".",
		}}
		resp.Answer = append(resp.Answer, rr)
		return resp
	})
	c, err := NewClient(srv.URL, TLSConfigOption(&tls.Config{InsecureSkipVerify: true}))
	require.NoError(t, err)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.ErrorIs(t, err, ErrNoECHConfig)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.ErrorIs(t, err, ErrNoECHConfig)
	require.Equal(t, int32(1), count.Load())
}

func TestConfigList_DoHFailure(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, TLSConfigOption(&tls.Config{InsecureSkipVerify: true}))
	require.NoError(t, err)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.Error(t, err)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.Error(t, err)
	require.Equal(t, int32(1), count.Load())
}

func TestConfigList_TTLExpiry(t *testing.T) {
	list := newTestECHConfigList(t)
	var count atomic.Int32
	srv := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		count.Add(1)
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
	c, err := NewClient(srv.URL, TLSConfigOption(&tls.Config{InsecureSkipVerify: true}))
	require.NoError(t, err)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	c.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	_, err = c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, int32(2), count.Load())
}

func TestConfigList_Disabled(t *testing.T) {
	c, err := NewClient("https://example.com", TLSConfigOption(&tls.Config{InsecureSkipVerify: true}))
	require.NoError(t, err)
	c.Disable("example.com", time.Minute)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.ErrorIs(t, err, ErrDisabled)
}

func TestConfigList_SetConfigList(t *testing.T) {
	list := newTestECHConfigList(t)
	c, err := NewClient("https://example.com", TLSConfigOption(&tls.Config{InsecureSkipVerify: true}))
	require.NoError(t, err)
	c.SetConfigList("example.com", list)
	got, err := c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, list, got)
}

func TestConfigList_TTLOverride(t *testing.T) {
	list := newTestECHConfigList(t)
	var count atomic.Int32
	srv := newDoHServer(t, func(req *dns.Msg) *dns.Msg {
		count.Add(1)
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
	c, err := NewClient(srv.URL, TLSConfigOption(&tls.Config{InsecureSkipVerify: true}), TTLOption(10*time.Minute))
	require.NoError(t, err)
	_, err = c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	c.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	_, err = c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, int32(1), count.Load())
	c.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	_, err = c.ConfigList(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, int32(2), count.Load())
}
