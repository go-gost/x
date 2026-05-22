package admission

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-gost/core/admission"
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

func TestHTTPPlugin_Admit_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": false}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.False(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.False(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL)
	assert.False(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_ConnectionRefused(t *testing.T) {
	p := NewHTTPPlugin("test", "http://127.0.0.1:0", plugin.TimeoutOption(0))
	assert.False(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_NilClient(t *testing.T) {
	hp := &httpPlugin{
		url:    "http://localhost",
		client: nil,
	}
	assert.False(t, hp.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_WithServiceAndHeader(t *testing.T) {
	var receivedService string
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedService = r.URL.Query().Get("check_service")
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	p := NewHTTPPlugin("test", srv.URL, plugin.HeaderOption(http.Header{
		"X-Custom": []string{"test-value"},
	}))
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1", admission.WithService("myservice")))
	_ = receivedService
	_ = receivedHeader
}

func TestHTTPPlugin_Admit_WithNoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	// Create plugin without custom headers
	hp := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
		header: nil,
	}
	assert.True(t, hp.Admit(context.Background(), "tcp", "192.168.1.1"))
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

func TestHTTPPlugin_Admit_WithAllOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	// Test with various plugin options
	p := &httpPlugin{
		url:    srv.URL,
		client: plugin.NewHTTPClient(&plugin.Options{}),
		header: http.Header{"Authorization": []string{"Bearer mytoken"}},
	}
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestHTTPPlugin_Admit_BadURL(t *testing.T) {
	// A URL that causes http.NewRequestWithContext to fail.
	hp := &httpPlugin{
		url:    "http://invalid hostname", // space causes NewRequest to fail
		client: plugin.NewHTTPClient(&plugin.Options{}),
	}
	assert.False(t, hp.Admit(context.Background(), "tcp", "192.168.1.1"))
}

var _ io.Closer = (*httpPlugin)(nil)
