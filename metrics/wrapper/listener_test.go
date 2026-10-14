package wrapper

import (
	"errors"
	"net"
	"testing"

	xmetrics "github.com/go-gost/x/metrics"
)

// enableMetrics turns metrics on for the duration of the test and restores
// the previous state afterwards. WrapListener skips connection wrapping when
// metrics are disabled, so tests that observe wrapped conns must enable them.
func enableMetrics(t *testing.T) {
	t.Helper()
	prev := xmetrics.IsEnabled()
	xmetrics.Enable(true)
	t.Cleanup(func() { xmetrics.Enable(prev) })
}

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
	enableMetrics(t)

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

// TestWrapListenerMetricsDisabled documents the splice(2) optimization: with
// metrics disabled the listener is returned unchanged and accepted
// connections are not wrapped, leaving bare *net.TCPConn for the
// forwarding layer.
func TestWrapListenerMetricsDisabled(t *testing.T) {
	prev := xmetrics.IsEnabled()
	xmetrics.Enable(false)
	t.Cleanup(func() { xmetrics.Enable(prev) })

	client, server := net.Pipe()
	defer client.Close()

	ln := &mockListener{
		accept: func() (net.Conn, error) {
			return server, nil
		},
	}

	wrapped := WrapListener("test-svc", ln)
	if wrapped != net.Listener(ln) {
		t.Fatalf("WrapListener returned %T, want the listener unchanged when metrics are disabled", wrapped)
	}

	c, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	if _, ok := c.(*serverConn); ok {
		t.Error("accepted connection should not be wrapped when metrics are disabled")
	}
	c.Close()
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
