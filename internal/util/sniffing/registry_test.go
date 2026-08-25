package sniffing

import (
	"context"
	"net"
	"testing"
)

// TestRegisterGet verifies a handler can be registered and looked up by proto.
func TestRegisterGet(t *testing.T) {
	const proto = "testproto-get"
	called := false
	Register(proto, func(s *Sniffer, _ context.Context, _ string, _ net.Conn, _ ...HandleOption) error {
		called = true
		return nil
	})
	defer protoHandlers.Delete(proto)

	fn, ok := Get(proto)
	if !ok {
		t.Fatal("Get: handler not found")
	}
	if err := fn(&Sniffer{}, context.Background(), "tcp", nil); err != nil {
		t.Fatalf("fn() error = %v", err)
	}
	if !called {
		t.Fatal("registered handler was not called")
	}
	if _, ok := Get("no-such-proto"); ok {
		t.Fatal("Get: unexpected handler for unknown proto")
	}
}

// TestRegisterDuplicate verifies registering the same proto twice panics.
func TestRegisterDuplicate(t *testing.T) {
	const proto = "testproto-dup"
	Register(proto, func(*Sniffer, context.Context, string, net.Conn, ...HandleOption) error {
		return nil
	})
	defer protoHandlers.Delete(proto)

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	Register(proto, func(*Sniffer, context.Context, string, net.Conn, ...HandleOption) error {
		return nil
	})
}

// TestDispatch_Unknown verifies Dispatch falls through (false, nil) for an
// unregistered proto.
func TestDispatch_Unknown(t *testing.T) {
	handled, err := Dispatch(&Sniffer{}, context.Background(), "tcp", nil, "no-such-proto")
	if handled {
		t.Fatal("Dispatch: unknown proto handled = true, want false")
	}
	if err != nil {
		t.Fatalf("Dispatch: err = %v, want nil", err)
	}
}

// TestDispatch_Known verifies Dispatch routes a registered proto to its handler.
func TestDispatch_Known(t *testing.T) {
	const proto = "testproto-known"
	called := false
	Register(proto, func(s *Sniffer, _ context.Context, _ string, _ net.Conn, _ ...HandleOption) error {
		called = true
		return nil
	})
	defer protoHandlers.Delete(proto)

	handled, err := Dispatch(&Sniffer{}, context.Background(), "tcp", nil, proto)
	if !handled {
		t.Fatal("Dispatch: known proto handled = false, want true")
	}
	if err != nil {
		t.Fatalf("Dispatch: err = %v, want nil", err)
	}
	if !called {
		t.Fatal("Dispatch: registered handler was not called")
	}
}
