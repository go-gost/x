package remote

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/x/internal/util/sniffing"
	xrecorder "github.com/go-gost/x/recorder"
)

// ---------------------------------------------------------------------------
// SnifferBuilder
// ---------------------------------------------------------------------------

func TestSnifferBuilder(t *testing.T) {
	h := newTestHandler()
	h.sniffer.Websocket = true
	h.sniffer.WebsocketSampleRate = 0.5
	h.sniffer.ReadTimeout = 30 * time.Second

	sniffer := h.sniffer.Build()

	if !sniffer.Websocket {
		t.Error("expected Websocket to be true")
	}
	if sniffer.WebsocketSampleRate != 0.5 {
		t.Errorf("expected 0.5, got %f", sniffer.WebsocketSampleRate)
	}
	if sniffer.ReadTimeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", sniffer.ReadTimeout)
	}
}

// ---------------------------------------------------------------------------
// sniffingDial
// ---------------------------------------------------------------------------

func TestSniffingDial_Success(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	ro := &xrecorder.HandlerRecorderObject{}

	cc, err := h.sniffingDial(context.Background(), "tcp", "example.com:80", ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cc.Close()

	if ro.Route == "" {
		t.Log("route is empty (mock does not populate context buffer)")
	}
}

func TestSniffingDial_RouterError(t *testing.T) {
	expectedErr := errors.New("dial failed")
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, expectedErr
		},
	}))
	ro := &xrecorder.HandlerRecorderObject{}

	_, err := h.sniffingDial(context.Background(), "tcp", "example.com:80", ro)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

// ---------------------------------------------------------------------------
// handleSniffedProtocol
// ---------------------------------------------------------------------------

func TestHandleSniffedProtocol_UnknownProto(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), "ssh")
	if handled {
		t.Error("expected handled=false for unknown proto")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestHandleSniffedProtocol_EmptyProto(t *testing.T) {
	h := newInitdHandler()
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), "")
	if handled {
		t.Error("expected handled=false for empty proto")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestHandleSniffedProtocol_HTTP(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dial not configured in test")
		},
	}))
	conn := newStringConn([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), sniffing.ProtoHTTP)

	if !handled {
		t.Error("expected handled=true for HTTP proto")
	}
	if err == nil {
		t.Log("sniffer processed HTTP request without error")
	}
}

func TestHandleSniffedProtocol_TLS(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dial not configured in test")
		},
	}))
	conn := newStringConn([]byte{
		0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x03, 0x01,
	})
	ro := &xrecorder.HandlerRecorderObject{}

	handled, err := h.handleSniffedProtocol(context.Background(), conn, ro, nopLog(), sniffing.ProtoTLS)

	if !handled {
		t.Error("expected handled=true for TLS proto")
	}
	if err == nil {
		t.Log("sniffer processed TLS ClientHello without error")
	}
}
