package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDialer_Dial_DialFunc(t *testing.T) {
	customErr := errors.New("custom dial")
	d := &Dialer{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, customErr
		},
	}

	_, err := d.Dial(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Error("expected error from custom DialFunc")
	}
	if err != customErr {
		t.Errorf("expected custom error, got %v", err)
	}
}

func TestDialer_Dial_DialFunc_Success(t *testing.T) {
	expectedConn := &net.TCPConn{}
	d := &Dialer{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return expectedConn, nil
		},
	}

	conn, err := d.Dial(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if conn != expectedConn {
		t.Error("expected the connection from DialFunc")
	}
}

func TestDefaultTimeout(t *testing.T) {
	if DefaultTimeout == 0 {
		t.Error("DefaultTimeout should be non-zero")
	}
}

func TestDefaultNetDialer(t *testing.T) {
	if DefaultNetDialer == nil {
		t.Error("DefaultNetDialer should not be nil")
	}
}

func TestDialer_Dial_DialFunc_Unix(t *testing.T) {
	d := &Dialer{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("unix error")
		},
	}

	_, err := d.Dial(context.Background(), "unix", "/tmp/test.sock")
	if err == nil {
		t.Error("expected error from DialFunc")
	}
}

func TestDialer_Dial_NonStrictInterface(t *testing.T) {
	// Non-existent interface, non-strict mode
	d := &Dialer{
		Interface: "nonexistent_xyz",
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}

	_, err := d.Dial(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Error("expected error from dial")
	}
}

func TestDialer_Dial_StrictInterfaceError(t *testing.T) {
	// Strict mode: non-existent interface returns error immediately
	d := &Dialer{
		Interface: "nonexistent_xyz!",
	}

	_, err := d.Dial(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Error("expected error from strict interface")
	}
}

func TestDialer_Dial_InterfaceWithIP(t *testing.T) {
	// Use IP address as interface name in non-strict mode
	d := &Dialer{
		Interface: "203.0.113.1",
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}

	_, err := d.Dial(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Error("expected error from dial")
	}
}

func TestDialer_Dial_InterfaceLoopback(t *testing.T) {
	// Use loopback interface
	d := &Dialer{
		Interface: "lo",
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}

	_, err := d.Dial(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Error("expected error from dial")
	}
}

func TestDialer_Dial_UDPInterface(t *testing.T) {
	d := &Dialer{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("udp dial failed")
		},
	}

	_, err := d.Dial(context.Background(), "udp", "")
	if err == nil {
		t.Error("expected error from dial")
	}
}
