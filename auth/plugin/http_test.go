package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-gost/core/auth"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPPlugin(t *testing.T) {
	p := NewHTTPPlugin("test", "http://localhost:9999")
	require.NotNil(t, p)

	hp, ok := p.(*httpPlugin)
	require.True(t, ok)
	assert.Equal(t, "http://localhost:9999", hp.url)
	assert.NotNil(t, hp.client)
	assert.NotNil(t, hp.log)
}

func TestHTTPPlugin_Authenticate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "user1"}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "user1", id)
}

func TestHTTPPlugin_Authenticate_Fail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": false, "id": ""}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestHTTPPlugin_Authenticate_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestHTTPPlugin_Authenticate_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestHTTPPlugin_Authenticate_ConnectionRefused(t *testing.T) {
	p := NewHTTPPlugin("test", "http://127.0.0.1:0", plugin.TimeoutOption(0))
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestHTTPPlugin_Authenticate_NilClient(t *testing.T) {
	hp := &httpPlugin{
		url:    "http://localhost",
		client: nil,
	}
	id, ok := hp.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestHTTPPlugin_Authenticate_WithService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "svc"}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	id, ok := p.Authenticate(context.Background(), "u", "p", auth.WithService("myservice"))
	assert.True(t, ok)
	assert.Equal(t, "svc", id)
}

func TestHTTPPlugin_Authenticate_WithHeader(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "hdr"}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.HeaderOption(http.Header{
		"X-Custom": []string{"test-value"},
	}))
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "hdr", id)
	assert.Equal(t, "test-value", receivedHeader)
}

func TestHTTPPlugin_Authenticate_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "nohdr"}`))
	}))
	defer srv.Close()

	hp := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
		header: nil,
	}
	id, ok := hp.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "nohdr", id)
}

func TestHTTPPlugin_Authenticate_WithClientAddr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "addr"}`))
	}))
	defer srv.Close()

	hp := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
	}
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5678})
	id, ok := hp.Authenticate(ctx, "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "addr", id)
}

func TestHTTPPlugin_Authenticate_WithoutClientAddr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "noaddr"}`))
	}))
	defer srv.Close()

	hp := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
	}
	id, ok := hp.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "noaddr", id)
}

func TestHTTPPlugin_Authenticate_BadURL(t *testing.T) {
	hp := &httpPlugin{
		url:    "http://invalid hostname",
		client: plugin.NewHTTPClient(&plugin.Options{}),
	}
	id, ok := hp.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestHTTPPlugin_Authenticate_WithAllOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true, "id": "all"}`))
	}))
	defer srv.Close()

	hp := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
		header: http.Header{"Authorization": []string{"Bearer mytoken"}},
	}
	id, ok := hp.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "all", id)
}
