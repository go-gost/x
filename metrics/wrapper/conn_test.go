package wrapper

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	xio "github.com/go-gost/x/internal/io"
)

func TestWrapConnNil(t *testing.T) {
	if c := WrapConn("svc", nil); c != nil {
		t.Error("WrapConn(nil) should return nil")
	}
}

func TestWrapPacketConnNil(t *testing.T) {
	if pc := WrapPacketConn("svc", nil); pc != nil {
		t.Error("WrapPacketConn(nil) should return nil")
	}
}

func TestWrapUDPConnNil(t *testing.T) {
	if uc := WrapUDPConn("svc", nil); uc != nil {
		t.Error("WrapUDPConn(nil) should return nil")
	}
}

func TestWrapConnReadWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn("test-svc", server)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		client.Write([]byte("hello"))
	}()

	buf := make([]byte, 1024)
	n, err := wrapped.Read(buf)
	wg.Wait()

	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes, got %d", n)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}

	// Write through the wrapped conn.
	go func() {
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		if err != nil {
			t.Errorf("client Read error: %v", err)
			return
		}
		if n != 5 || string(buf[:n]) != "world" {
			t.Errorf("expected 'world', got %q", string(buf[:n]))
		}
	}()

	nw, err := wrapped.Write([]byte("world"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if nw != 5 {
		t.Errorf("expected 5 bytes written, got %d", nw)
	}
}

func TestWrapConnSyscallConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn("test-svc", server)

	// SyscallConn should not panic. The return values depend on the underlying
	// connection type.
	_, _ = wrapped.(*serverConn).SyscallConn()
}

func TestWrapConnCloseReadCloseWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn("test-svc", server)

	// net.Pipe does not implement CloseRead/CloseWrite, so these should
	// return ErrUnsupported.
	err := wrapped.(*serverConn).CloseRead()
	if err != xio.ErrUnsupported {
		t.Errorf("CloseRead: expected ErrUnsupported, got %v", err)
	}

	err = wrapped.(*serverConn).CloseWrite()
	if err != xio.ErrUnsupported {
		t.Errorf("CloseWrite: expected ErrUnsupported, got %v", err)
	}
}

func TestWrapConnContext(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn("test-svc", server)

	// net.Pipe does not implement ctx.Context, so Context() returns nil.
	ctx := wrapped.(*serverConn).Context()
	if ctx != nil {
		t.Errorf("expected nil context, got %v", ctx)
	}
}

// mockPacketConn implements net.PacketConn for testing.
type mockPacketConn struct {
	readFrom func([]byte) (int, net.Addr, error)
	writeTo  func([]byte, net.Addr) (int, error)
}

func (m *mockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return m.readFrom(p)
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return m.writeTo(p, addr)
}

func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) LocalAddr() net.Addr                 { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }
func (m *mockPacketConn) SetDeadline(t time.Time) error       { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error   { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error  { return nil }

func TestWrapPacketConnReadFromWriteTo(t *testing.T) {
	testAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}

	mock := &mockPacketConn{
		readFrom: func(p []byte) (int, net.Addr, error) {
			copy(p, []byte("data"))
			return 4, testAddr, nil
		},
		writeTo: func(p []byte, addr net.Addr) (int, error) {
			return len(p), nil
		},
	}

	wrapped := WrapPacketConn("test-svc", mock)

	// ReadFrom
	buf := make([]byte, 1024)
	n, addr, err := wrapped.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 bytes, got %d", n)
	}
	if addr.String() != testAddr.String() {
		t.Errorf("expected addr %s, got %s", testAddr, addr)
	}

	// WriteTo
	nw, err := wrapped.WriteTo([]byte("reply"), testAddr)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if nw != 5 {
		t.Errorf("expected 5 bytes written, got %d", nw)
	}
}

func TestWrapPacketConnContext(t *testing.T) {
	mock := &mockPacketConn{
		readFrom: func(p []byte) (int, net.Addr, error) { return 0, nil, io.EOF },
		writeTo:  func(p []byte, addr net.Addr) (int, error) { return len(p), nil },
	}

	wrapped := WrapPacketConn("test-svc", mock)

	// mockPacketConn does not implement ctx.Context
	ctx := wrapped.(*packetConn).Context()
	if ctx != nil {
		t.Errorf("expected nil context, got %v", ctx)
	}
}

func TestWrapConnRemoteAddr(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn("test-svc", server)

	// The wrapped conn should expose the underlying remote address.
	if wrapped.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestWrapConnNilLabels(t *testing.T) {
	// When the remote address has no port, SplitHostPort may fail.
	// WrapConn should still succeed and the host may be empty.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn("test-svc", server)

	// Read should not panic even with potentially malformed addresses.
	// net.Pipe addresses are well-formed so this is a smoke test.
	buf := make([]byte, 1)
	go client.Write([]byte{0x01})
	_, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
}
