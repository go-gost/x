package remote

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	ictx "github.com/go-gost/x/internal/ctx"
	xmd "github.com/go-gost/x/metadata"
	xrecorder "github.com/go-gost/x/recorder"
)

// ---------------------------------------------------------------------------
// handleRawForwarding
// ---------------------------------------------------------------------------

func TestHandleRawForwarding_NilHop(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no route to host")
		},
	}))
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err == nil {
		t.Fatal("expected error when hop is nil")
	}
}

func TestHandleRawForwarding_NodeUnavailable(t *testing.T) {
	h := newInitdHandler()
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return nil
		},
	})
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err == nil {
		t.Fatal("expected error when node is nil")
	}
	if !errors.Is(err, errNodeNotAvailable) {
		t.Errorf("expected errNodeNotAvailable, got %v", err)
	}
}

func TestHandleRawForwarding_DialError(t *testing.T) {
	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("test-node", "127.0.0.1:9999")
		},
	})
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err == nil {
		t.Fatal("expected error when dial fails")
	}
	if ro.Host != "127.0.0.1:9999" {
		t.Errorf("expected host 127.0.0.1:9999, got %s", ro.Host)
	}
}

func TestHandleRawForwarding_Success(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1:80", Name: "upstream"}
		},
	})
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ro.Host != "10.0.0.1:80" {
		t.Errorf("expected host 10.0.0.1:80, got %s", ro.Host)
	}
	if ro.Network != "tcp" {
		t.Errorf("expected network tcp, got %s", ro.Network)
	}
	if ro.SrcAddr == "" {
		t.Error("expected SrcAddr to be set")
	}
	if ro.DstAddr == "" {
		t.Error("expected DstAddr to be set")
	}
}

func TestHandleRawForwarding_AddrWithoutPort(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.1", Name: "noport"}
		},
	})
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ro.Host != "10.0.0.1:0" {
		t.Errorf("expected ':0' appended to addr, got %s", ro.Host)
	}
}

func TestHandleRawForwarding_UnixSocket(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("unix-node", "/tmp/unix.sock",
				chain.NetworkNodeOption("unix"),
			)
		},
	})
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.Network != "unix" {
		t.Errorf("expected network 'unix', got '%s'", ro.Network)
	}
}

func TestHandleRawForwarding_MarkerReset(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return chain.NewNode("target", "10.0.0.1:80")
		},
	})
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(context.Background(), conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.Host != "10.0.0.1:80" {
		t.Errorf("expected host '10.0.0.1:80', got '%s'", ro.Host)
	}
}

func TestHandleRawForwarding_ContextHost(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	h := newInitdHandler(withRouter(&mockRouter{
		opts: &chain.RouterOptions{},
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return server, nil
		},
	}))
	h.Forward(&mockHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return &chain.Node{Addr: "10.0.0.2:80"}
		},
	})
	ctx := ictx.ContextWithMetadata(context.Background(), xmd.NewMetadata(map[string]any{
		"host": "10.0.0.99:8080",
	}))
	conn := newStringConn(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.handleRawForwarding(ctx, conn, ro, nopLog(), "tcp", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.Host != "10.0.0.99:8080" {
		t.Errorf("expected host from context, got '%s'", ro.Host)
	}
}
