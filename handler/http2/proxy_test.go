package http2

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-gost/core/handler"
	xrecorder "github.com/go-gost/x/recorder"
)

func TestDecodeServerName(t *testing.T) {
	encode := func(name string) string {
		data := []byte(name)
		checksum := make([]byte, 4)
		binary.BigEndian.PutUint32(checksum, crc32.ChecksumIEEE(data))
		payload := base64.RawURLEncoding.EncodeToString(data)
		return base64.RawURLEncoding.EncodeToString(append(checksum, []byte(payload)...))
	}

	h := newTestHandler()

	t.Run("valid", func(t *testing.T) {
		encoded := encode("example.com:443")
		got, err := h.decodeServerName(encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "example.com:443" {
			t.Errorf("got %q, want %q", got, "example.com:443")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := h.decodeServerName("!!!invalid!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := h.decodeServerName(base64.RawURLEncoding.EncodeToString([]byte("ab")))
		if err == nil {
			t.Error("expected error for short input")
		}
	})

	t.Run("wrong checksum", func(t *testing.T) {
		data := []byte("target")
		badChecksum := make([]byte, 4)
		binary.BigEndian.PutUint32(badChecksum, 0xDEADBEEF)
		payload := base64.RawURLEncoding.EncodeToString(data)
		encoded := base64.RawURLEncoding.EncodeToString(append(badChecksum, []byte(payload)...))
		_, err := h.decodeServerName(encoded)
		if err == nil {
			t.Error("expected error for wrong checksum")
		}
	})
}

func TestWriteResponse(t *testing.T) {
	h := newTestHandler()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Test": []string{"value"}},
		Body:       io.NopCloser(strings.NewReader("response body")),
	}
	w := httptest.NewRecorder()
	if err := h.writeResponse(w, resp); err != nil {
		t.Fatalf("writeResponse: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("X-Test") != "value" {
		t.Errorf("X-Test = %q, want %q", w.Header().Get("X-Test"), "value")
	}
	if w.Body.String() != "response body" {
		t.Errorf("body = %q, want %q", w.Body.String(), "response body")
	}
}

func TestForwardRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	h := newTestHandler()
	cc, err := net.Dial("tcp", strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	defer cc.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	w := httptest.NewRecorder()

	if err := h.forwardRequest(w, req, cc); err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("X-Backend") != "ok" {
		t.Errorf("X-Backend = %q, want %q", w.Header().Get("X-Backend"), "ok")
	}
	if w.Body.String() != "backend response" {
		t.Errorf("body = %q, want %q", w.Body.String(), "backend response")
	}
}

func TestForwardRequest_WriteError(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	client, server := net.Pipe()
	server.Close()
	defer client.Close()

	err := h.forwardRequest(httptest.NewRecorder(), req, client)
	if err == nil {
		t.Error("expected error from failed write")
	}
}

func TestRoundTrip_NilRequest(t *testing.T) {
	h := newTestHandler()
	h.Init(testMD(map[string]any{}))

	if err := h.roundTrip(context.Background(), nil, nil, nil, &testLogger{}); err != nil {
		t.Errorf("roundTrip with nil args: %v", err)
	}
}

func TestRoundTrip_AuthFailed(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.Init(testMD(map[string]any{}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.roundTrip(context.Background(), w, req, ro, &testLogger{})
	if err != ErrAuthFailed {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

func TestRoundTrip_ProbeResistanceHost(t *testing.T) {
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("decoy response"))
	}))
	defer decoy.Close()

	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	decoyAddr := strings.TrimPrefix(decoy.URL, "http://")
	h.md.probeResistance = &probeResistance{Type: "host", Value: decoyAddr}
	h.Init(testMD(map[string]any{}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.roundTrip(context.Background(), w, req, ro, &testLogger{})
	if err != ErrAuthFailed {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("decoy status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.String() != "decoy response" {
		t.Errorf("decoy body = %q, want %q", w.Body.String(), "decoy response")
	}
}

func TestRoundTrip_ProbeResistanceHostDialError(t *testing.T) {
	h := newTestHandler(handler.AutherOption(&testAuther{ok: false}))
	h.md.probeResistance = &probeResistance{Type: "host", Value: "127.0.0.1:1"} // unreachable
	h.Init(testMD(map[string]any{}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.roundTrip(context.Background(), w, req, ro, &testLogger{})
	if err != ErrAuthFailed {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
	// Should get a 503 on dial failure.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
