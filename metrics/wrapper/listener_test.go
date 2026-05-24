package wrapper

import (
	"errors"
	"net"
	"testing"
)

func TestWrapListenerNil(t *testing.T) {
	if ln := WrapListener("svc", nil); ln != nil {
		t.Error("WrapListener(nil) should return nil")
	}
}

// mockListener implements net.Listener for testing.
type mockListener struct {
	accept func() (net.Conn, error)
}

func (l *mockListener) Accept() (net.Conn, error) { return l.accept() }
func (l *mockListener) Close() error              { return nil }
func (l *mockListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080} }

func TestWrapListenerAccept(t *testing.T) {
	client, server := net.Pipe()

	ln := &mockListener{
		accept: func() (net.Conn, error) {
			return server, nil
		},
	}

	wrapped := WrapListener("test-svc", ln)

	c, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	if c == nil {
		t.Fatal("accepted connection should not be nil")
	}

	// The accepted connection should be a *serverConn (wrapped by WrapConn).
	if _, ok := c.(*serverConn); !ok {
		t.Errorf("accepted connection should be *serverConn, got %T", c)
	}

	client.Close()
	c.Close()
}

func TestWrapListenerAcceptError(t *testing.T) {
	testErr := errors.New("accept failed")
	ln := &mockListener{
		accept: func() (net.Conn, error) {
			return nil, testErr
		},
	}

	wrapped := WrapListener("test-svc", ln)

	c, err := wrapped.Accept()
	if err != testErr {
		t.Errorf("expected error %v, got %v", testErr, err)
	}
	if c != nil {
		t.Error("connection should be nil on error")
	}
}

func TestWrapListenerAddr(t *testing.T) {
	ln := &mockListener{
		accept: func() (net.Conn, error) { return nil, errors.New("not used") },
	}

	wrapped := WrapListener("test-svc", ln)

	if wrapped.Addr() == nil {
		t.Error("Addr should not be nil")
	}
}
