package relay

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	xio "github.com/go-gost/x/internal/io"
)

// plainConn is a net.Conn without the half-close interfaces.
type plainConn struct{}

func (c *plainConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *plainConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *plainConn) Close() error                       { return nil }
func (c *plainConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *plainConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *plainConn) SetDeadline(t time.Time) error      { return nil }
func (c *plainConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *plainConn) SetWriteDeadline(t time.Time) error { return nil }

// halfCloseConn is a net.Conn that also implements the xio half-close
// interfaces, like the QUIC conn does.
type halfCloseConn struct {
	plainConn
	readClosed  bool
	writeClosed bool
}

func (c *halfCloseConn) CloseRead() error  { c.readClosed = true; return nil }
func (c *halfCloseConn) CloseWrite() error { c.writeClosed = true; return nil }

// tcpConn embeds the net.Conn interface, so the half-close methods of the
// conn it wraps are not promoted. Pipe's halfClose then always falls back
// to dst.Close(), which tears down the whole connection instead of
// half-closing it.
func TestTCPConnExposesHalfClose(t *testing.T) {
	inner := &halfCloseConn{}
	tc := &tcpConn{Conn: inner}

	cr, ok := interface{}(tc).(xio.CloseRead)
	if !ok {
		t.Fatal("tcpConn does not implement xio.CloseRead")
	}
	cw, ok := interface{}(tc).(xio.CloseWrite)
	if !ok {
		t.Fatal("tcpConn does not implement xio.CloseWrite")
	}

	if err := cr.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !inner.readClosed {
		t.Error("CloseRead was not forwarded to the wrapped conn")
	}
	if !inner.writeClosed {
		t.Error("CloseWrite was not forwarded to the wrapped conn")
	}
}

// When the wrapped conn does not support half-close, tcpConn must report
// ErrUnsupported so that halfClose falls back to a full close.
func TestTCPConnHalfCloseUnsupported(t *testing.T) {
	tc := &tcpConn{Conn: &plainConn{}}

	cr, ok := interface{}(tc).(xio.CloseRead)
	if !ok {
		t.Fatal("tcpConn does not implement xio.CloseRead")
	}
	if err := cr.CloseRead(); !errors.Is(err, xio.ErrUnsupported) {
		t.Fatalf("CloseRead = %v, want %v", err, xio.ErrUnsupported)
	}

	cw, ok := interface{}(tc).(xio.CloseWrite)
	if !ok {
		t.Fatal("tcpConn does not implement xio.CloseWrite")
	}
	if err := cw.CloseWrite(); !errors.Is(err, xio.ErrUnsupported) {
		t.Fatalf("CloseWrite = %v, want %v", err, xio.ErrUnsupported)
	}
}

// The wrapped conn is a net.Conn, so the rest of the interface must keep
// working.
func TestTCPConnStillAConn(t *testing.T) {
	tc := &tcpConn{Conn: &plainConn{}}
	var _ net.Conn = tc

	// A read deadline must reach the wrapped conn.
	if err := tc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
