package relay

import (
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/relay"
)

func newForwardHandler(t *testing.T, opts ...handler.Option) *relayHandler {
	t.Helper()
	// Default: provide a working router
	defaultOpts := []handler.Option{
		handler.LoggerOption(&testLogger{}),
		handler.RouterOption(&mockRouter{
			dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
				pr, pw := net.Pipe()
				pw.Close()
				return pr, nil
			},
		}),
	}
	rh := newInitdHandler(t, append(defaultOpts, opts...)...)
	return rh
}

func TestHandleForward_NoTarget(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return nil
		},
	}
	rh := newForwardHandler(t)
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err == nil || err.Error() != "target not available" {
		t.Errorf("err = %v, want target not available", err)
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusServiceUnavailable)
	}
}

func TestHandleForward_DialSucceeds(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return makeTestNode("example.com:80")
		},
	}
	rh := newForwardHandler(t)
	rh.md.noDelay = true
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleForward_DialFails(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return makeTestNode("example.com:80")
		},
	}
	rh := newInitdHandler(t,
		handler.LoggerOption(&testLogger{}),
		handler.RouterOption(&mockRouter{
			dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
				return nil, net.UnknownNetworkError("mock failure")
			},
		}),
	)
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err == nil {
		t.Fatal("expected error")
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusHostUnreachable {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusHostUnreachable)
	}
}

func TestHandleForward_NoDelay(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return makeTestNode("example.com:80")
		},
	}
	rh := newForwardHandler(t)
	rh.md.noDelay = true
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleForward_UDP(t *testing.T) {
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return makeTestNode("example.com:53")
		},
	}
	rh := newForwardHandler(t)
	rh.md.noDelay = true
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:53", "udp")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleForward_NilMarker(t *testing.T) {
	// Create a node with no marker (nil Marker)
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return chain.NewNode("test", "example.com:80")
		},
	}
	rh := newForwardHandler(t)
	rh.md.noDelay = true
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestHandleForward_WithObserver(t *testing.T) {
	obs := &fakeObserver{eventsCh: make(chan []observer.Event, 10)}
	mh := &mockHop{
		selectFn: func(ctx context.Context) *chain.Node {
			return makeTestNode("example.com:80")
		},
	}
	rh := newForwardHandler(t,
		handler.ObserverOption(obs),
		handler.ServiceOption("test-svc"),
	)
	rh.md.noDelay = true
	rh.Forward(mh)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}