package net

import (
	"errors"
	"io"
	"net"
	"testing"

	xio "github.com/go-gost/x/internal/io"
)

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"::1", false},
		{"[::1]:8080", false},
		{"", false},
		{":8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := IsIPv4(tt.address); got != tt.want {
				t.Errorf("IsIPv4(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

// mockConn implements net.Conn for testing
type mockConn struct {
	net.Conn
	readErr  error
	writeErr error
}

func (m *mockConn) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return 0, nil
}

func (m *mockConn) Write(p []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(p), nil
}

func (m *mockConn) Close() error { return nil }

type mockAddr struct{}

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return "127.0.0.1:0" }

// mockReadWriteCloser implements io.ReadWriteCloser + CloseRead + CloseWrite
type mockReadWriteCloser struct {
	data         []byte
	readPos      int
	writeBuf     []byte
	closed       bool
	readClosed   bool
	writeClosed  bool
	readErr      error
	writeErr     error
	writeReadErr error
	deadlineFunc func() error
}

func (m *mockReadWriteCloser) Read(p []byte) (int, error) {
	if m.readClosed {
		return 0, net.ErrClosed
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockReadWriteCloser) Write(p []byte) (int, error) {
	if m.writeClosed {
		return 0, net.ErrClosed
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeBuf = append(m.writeBuf, p...)
	return len(p), nil
}

func (m *mockReadWriteCloser) Close() error {
	m.closed = true
	return nil
}

func (m *mockReadWriteCloser) CloseRead() error {
	m.readClosed = true
	return nil
}

func (m *mockReadWriteCloser) CloseWrite() error {
	m.writeClosed = true
	return xio.ErrUnsupported
}

func (m *mockReadWriteCloser) SetReadDeadline(t interface{}) error {
	if m.deadlineFunc != nil {
		return m.deadlineFunc()
	}
	return nil
}

func TestNewReadWriteConn(t *testing.T) {
	r := &mockReadWriteCloser{data: []byte("read data")}
	w := &mockReadWriteCloser{}
	c := &mockConn{}

	rwc := NewReadWriteConn(r, w, c)

	// Test Read
	buf := make([]byte, 9)
	n, err := rwc.Read(buf)
	if err != nil {
		t.Error(err)
	}
	if n != 9 || string(buf[:n]) != "read data" {
		t.Errorf("expected 'read data', got %q", string(buf[:n]))
	}

	// Test Write
	n, err = rwc.Write([]byte("write data"))
	if err != nil {
		t.Error(err)
	}
	if n != 10 {
		t.Errorf("expected 10 bytes written, got %d", n)
	}
}

func Test_readWriteConn_CloseRead_CloseWrite(t *testing.T) {
	r := &mockReadWriteCloser{}
	w := &mockReadWriteCloser{}
	c := &mockConn{}

	conn := NewReadWriteConn(r, w, c)

	if cr, ok := conn.(xio.CloseRead); ok {
		err := cr.CloseRead()
		if err == nil {
			t.Error("expected error when CloseRead on conn without CloseRead")
		}
	} else {
		t.Error("should implement CloseRead")
	}

	if cw, ok := conn.(xio.CloseWrite); ok {
		err := cw.CloseWrite()
		if err == nil {
			t.Error("expected error when CloseWrite on conn without CloseWrite")
		}
	} else {
		t.Error("should implement CloseWrite")
	}
}

// closeReadWriteConn implements both CloseRead and CloseWrite
type closeReadWriteConn struct {
	net.Conn
}

func (c *closeReadWriteConn) CloseRead() error  { return nil }
func (c *closeReadWriteConn) CloseWrite() error { return nil }
func (c *closeReadWriteConn) Close() error      { return nil }

func Test_readWriteConn_CloseRead_CloseWrite_supported(t *testing.T) {
	r := &mockReadWriteCloser{}
	w := &mockReadWriteCloser{}
	c := &closeReadWriteConn{}

	conn := NewReadWriteConn(r, w, c)

	if cr, ok := conn.(xio.CloseRead); ok {
		err := cr.CloseRead()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	} else {
		t.Error("should implement CloseRead")
	}

	if cw, ok := conn.(xio.CloseWrite); ok {
		err := cw.CloseWrite()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	} else {
		t.Error("should implement CloseWrite")
	}
}

// errReadWriteCloser returns errors on read/write, for error path testing
type errReadWriteCloser struct {
	*mockReadWriteCloser
}

func (m *errReadWriteCloser) Read(p []byte) (int, error) {
	return 0, errors.New("read error")
}

func (m *errReadWriteCloser) Write(p []byte) (int, error) {
	return 0, errors.New("write error")
}
