package http2

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
)

func TestKnockMatch(t *testing.T) {
	tests := []struct {
		hostname string
		knock    string
		want     bool
	}{
		{"", "", false},
		{"example.com", "", false},
		{"example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},
		{"example.com", "foo,example.com,bar", true},
		{"other.com", "foo, bar , baz", false},
		{"other.com", "foo,bar,baz", false},
		{"bar", "foo, bar , baz", true},
		{"BAR", "foo, bar , baz", true},
	}
	for _, tt := range tests {
		got := knockMatch(tt.hostname, tt.knock)
		if got != tt.want {
			t.Errorf("knockMatch(%q, %q) = %v, want %v", tt.hostname, tt.knock, got, tt.want)
		}
	}
}

func TestBasicProxyAuth(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name     string
		auth     string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{"empty", "", "", "", false},
		{"not basic", "Bearer token", "", "", false},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), "", "", false},
		{"valid", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), "user", "pass", true},
		{"password with colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass:word")), "user", "pass:word", true},
		{"invalid base64", "Basic not-valid-base64!!!", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, ok := h.basicProxyAuth(tt.auth)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
			if pass != tt.wantPass {
				t.Errorf("pass = %q, want %q", pass, tt.wantPass)
			}
		})
	}
}

type testAuther struct {
	ok bool
	id string
}

func (a *testAuther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	return a.id, a.ok
}

func TestAuthenticate(t *testing.T) {
	t.Run("no auther", func(t *testing.T) {
		h := newTestHandler()
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		w := httptest.NewRecorder()
		resp := &http.Response{Header: w.Header(), Body: io.NopCloser(strings.NewReader(""))}

		id, ok, _ := h.authenticate(context.Background(), w, req, resp, &testLogger{})
		if !ok {
			t.Error("expected ok without auther")
		}
		if id != "" {
			t.Errorf("id = %q, want empty", id)
		}
	})

	t.Run("auth succeeds", func(t *testing.T) {
		h := newTestHandler(handler.AutherOption(&testAuther{ok: true, id: "client1"}))
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
		w := httptest.NewRecorder()
		resp := &http.Response{Header: w.Header(), Body: io.NopCloser(strings.NewReader(""))}

		id, ok, _ := h.authenticate(context.Background(), w, req, resp, &testLogger{})
		if !ok {
			t.Error("expected ok with valid auth")
		}
		if id != "client1" {
			t.Errorf("id = %q, want %q", id, "client1")
		}
	})

	t.Run("auth fails - returns 407", func(t *testing.T) {
		h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		w := httptest.NewRecorder()
		resp := &http.Response{Header: w.Header(), Body: io.NopCloser(strings.NewReader(""))}

		_, ok, _ := h.authenticate(context.Background(), w, req, resp, &testLogger{})
		if ok {
			t.Error("expected !ok with failed auth")
		}
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
		}
		if !strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Basic") {
			t.Error("missing Proxy-Authenticate header")
		}
	})
}

func TestAuthenticate_ProbeResistanceCode(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.md.probeResistance = &probeResistance{Type: "code", Value: "503"}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}

	_, ok, _ := h.authenticate(context.Background(), w, req, resp, &testLogger{})
	if ok {
		t.Error("expected !ok")
	}
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestAuthenticate_ProbeResistanceKnockBypass(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.md.probeResistance = &probeResistance{Type: "code", Value: "403", Knock: "safe.example.com"}

	req := httptest.NewRequest(http.MethodGet, "http://safe.example.com/", nil)
	w := httptest.NewRecorder()
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}

	_, ok, _ := h.authenticate(context.Background(), w, req, resp, &testLogger{})
	if ok {
		t.Error("expected !ok")
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d (knock matched, probe resistance skipped)", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticate_ProbeResistanceHost(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.md.probeResistance = &probeResistance{Type: "host", Value: "127.0.0.1:9999"}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}

	_, ok, pipeTo := h.authenticate(context.Background(), w, req, resp, &testLogger{})
	if ok {
		t.Error("expected !ok")
	}
	if pipeTo != "127.0.0.1:9999" {
		t.Errorf("pipeTo = %q, want %q", pipeTo, "127.0.0.1:9999")
	}
}

func TestAuthenticate_ProbeResistanceHostKnockMatch(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.md.probeResistance = &probeResistance{Type: "host", Value: "127.0.0.1:9999", Knock: "example.com"}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}

	_, ok, pipeTo := h.authenticate(context.Background(), w, req, resp, &testLogger{})
	if ok {
		t.Error("expected !ok")
	}
	if pipeTo != "" {
		t.Errorf("pipeTo = %q, want empty (knock matched, probe resistance bypassed)", pipeTo)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestAuthenticate_CustomRealm(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.md.authBasicRealm = "testrealm"

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	resp := &http.Response{Header: w.Header(), Body: io.NopCloser(strings.NewReader(""))}

	_, ok, _ := h.authenticate(context.Background(), w, req, resp, &testLogger{})
	if ok {
		t.Error("expected !ok")
	}
	if !strings.Contains(resp.Header.Get("Proxy-Authenticate"), `realm="testrealm"`) {
		t.Errorf("Proxy-Authenticate = %q, want realm=testrealm", resp.Header.Get("Proxy-Authenticate"))
	}
}
