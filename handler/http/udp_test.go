package http

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/go-gost/core/handler"
	xrecorder "github.com/go-gost/x/recorder"
)

func TestHandleUDP_Disabled_WritesForbidden(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.enableUDP = false

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ro := &xrecorder.HandlerRecorderObject{}

	go func() {
		h.handleUDP(context.Background(), server, "", ro, &testLogger{})
	}()

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestHandleUDP_Enabled_NilRouter(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.enableUDP = true

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ro := &xrecorder.HandlerRecorderObject{}

	go func() {
		// OK response sent, then nil router causes error
		err := h.handleUDP(context.Background(), server, "", ro, &testLogger{})
		if err == nil {
			t.Log("expected error with nil router for UDP")
		}
	}()

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
