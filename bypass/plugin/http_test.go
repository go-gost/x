package bypass

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-gost/core/bypass"
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

func TestHTTPPlugin_Contains_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": false}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.False(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	// Non-200 returns true (fail-open)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	// Invalid JSON returns true (fail-open)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_ConnectionRefused(t *testing.T) {
	p := NewHTTPPlugin("test", "http://127.0.0.1:0", plugin.TimeoutOption(0))
	// Connection refused returns true (fail-open)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_NilClient(t *testing.T) {
	hp := &httpPlugin{
		url:    "http://localhost",
		client: nil,
	}
	// Nil client returns true (fail-open)
	assert.True(t, hp.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_WithService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1", bypass.WithService("myservice")))
}

func TestHTTPPlugin_Contains_WithHostAndPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1",
		bypass.WithHostOption("example.com"),
		bypass.WithPathOption("/api/v1"),
	))
}

func TestHTTPPlugin_Contains_WithCustomHeader(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.HeaderOption(http.Header{
		"X-Custom": []string{"test-value"},
	}))
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.Equal(t, "test-value", receivedHeader)
}

func TestHTTPPlugin_Contains_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	hp := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
		header: nil,
	}
	assert.True(t, hp.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Contains_BadURL(t *testing.T) {
	hp := &httpPlugin{
		url:    "http://invalid hostname", // space causes NewRequest to fail
		client: plugin.NewHTTPClient(&plugin.Options{}),
	}
	// Bad URL returns true (fail-open)
	assert.True(t, hp.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Close_NilClient(t *testing.T) {
	hp := &httpPlugin{client: nil}
	err := hp.Close()
	assert.NoError(t, err)
}

func TestHTTPPlugin_Close_WithClient(t *testing.T) {
	hp := &httpPlugin{
		client: plugin.NewHTTPClient(&plugin.Options{}),
	}
	err := hp.Close()
	assert.NoError(t, err)
}

func TestHTTPPlugin_IsWhitelist(t *testing.T) {
	hp := &httpPlugin{}
	assert.False(t, hp.IsWhitelist())
}

var _ io.Closer = (*httpPlugin)(nil)
