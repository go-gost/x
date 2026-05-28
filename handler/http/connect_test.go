package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/go-gost/core/handler"
	xrecorder "github.com/go-gost/x/recorder"
)

func TestSniffAndHandle_NoMatch(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.sniffing = true
		h.sniffer = &SnifferBuilder{}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("SSH-2.0-OpenSSH\r\n"))
	}()

	cc, _ := net.Pipe()
	defer cc.Close()

	handled, err := h.sniffAndHandle(context.Background(), server, cc, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Error("expected not handled for non-HTTP/TLS traffic")
	}
}

func TestDial_NilRouter(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}

	_, err := h.dial(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error from dial with nil router")
	}
}

func TestSniffAndHandle_TLS(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.sniffing = true
		h.sniffer = &SnifferBuilder{}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Write TLS ClientHello bytes (content type 0x16 = Handshake, followed by TLS version)
	go func() {
		client.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
	}()

	cc, _ := net.Pipe()
	defer cc.Close()

	handled, err := h.sniffAndHandle(context.Background(), server, cc, &xrecorder.HandlerRecorderObject{}, &testLogger{})
	if err != nil {
		t.Logf("sniff error (expected without proper recorder): %v", err)
	}
	if !handled {
		t.Error("expected handled for TLS traffic")
	}
}

func TestHandleConnect_NilRouter(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain response to prevent Pipe blocking
	go func() {
		io.ReadAll(server)
	}()

	resp := testConnectResp()
	err := h.handleConnect(context.Background(), client, &xrecorder.HandlerRecorderObject{}, &testLogger{}, "example.com:443", resp)
	if err == nil {
		t.Error("expected dial error with nil router")
	}
}

func TestHandleConnect_SniffingEnabled(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.proxyAgent = defaultProxyAgent
	h.md.readTimeout = 15
	h.md.sniffing = true
		h.sniffer = &SnifferBuilder{}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain response to prevent Pipe blocking
	go func() {
		io.ReadAll(server)
	}()

	resp := testConnectResp()
	err := h.handleConnect(context.Background(), client, &xrecorder.HandlerRecorderObject{}, &testLogger{}, "example.com:443", resp)
	if err == nil {
		t.Error("expected dial error with nil router")
	}
}

func testConnectResp() *http.Response {
	return &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
	}
}

func TestDial_HostHash(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.md.hash = "host"

	_, err := h.dial(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error from dial with nil router")
	}
}
