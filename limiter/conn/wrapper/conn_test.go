package wrapper

import (
	"context"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	xio "github.com/go-gost/x/internal/io"
)

type connWithCloseRead struct {
	net.Conn
	closeReadCalled bool
}

func (c *connWithCloseRead) CloseRead() error {
	c.closeReadCalled = true
	return nil
}

type connWithCloseWrite struct {
	net.Conn
	closeWriteCalled bool
}

func (c *connWithCloseWrite) CloseWrite() error {
	c.closeWriteCalled = true
	return nil
}

type connWithSyscall struct {
	net.Conn
}

func (c *connWithSyscall) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}

type connWithContext struct {
	net.Conn
}

func (c *connWithContext) Context() context.Context {
	return context.Background()
}

func TestWrapConn_NilLimiter(t *testing.T) {
	c := &mockConn{}
	wc := WrapConn(nil, c)
	if wc != c {
		t.Fatal("WrapConn should return original conn when limiter is nil")
	}
}

func TestWrapConn_WithLimiter(t *testing.T) {
	c := &mockConn{}
	lim := &allowLimiter{limit: 5}
	wc := WrapConn(lim, c)

	sc, ok := wc.(*serverConn)
	if !ok {
		t.Fatal("WrapConn should return *serverConn when limiter is not nil")
	}
	if sc.Conn != c {
		t.Fatal("inner conn should be the original")
	}
	if sc.limiter != lim {
		t.Fatal("limiter should be set")
	}
}

func TestServerConn_Close_ReleasesLimiter(t *testing.T) {
	c := &mockConn{}
	lim := &allowLimiter{limit: 1}
	lim.Allow(1) // acquire one

	sc := &serverConn{Conn: c, limiter: lim}
	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}
	if !c.closed {
		t.Fatal("inner conn should be closed")
	}
	// After Close, the limiter should have one slot released.
	if !lim.Allow(1) {
		t.Fatal("limiter should allow after close released a slot")
	}
}

func TestServerConn_Close_DoubleClose_ReleasesLimiterOnce(t *testing.T) {
	c := &mockConn{}
	lim := &allowLimiter{limit: 2}
	lim.Allow(2) // acquire both slots

	sc := &serverConn{Conn: c, limiter: lim}
	sc.Close() // first close: releases one slot
	sc.Close() // second close: must NOT release the second slot

	if !lim.Allow(1) {
		t.Fatal("first close should have released a slot")
	}
	if lim.Allow(1) {
		t.Fatal("second close released another slot: double-release bug")
	}
}

func TestServerConn_CloseRead_Supported(t *testing.T) {
	inner := &connWithCloseRead{Conn: &mockConn{}}
	sc := &serverConn{Conn: inner}
	if err := sc.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if !inner.closeReadCalled {
		t.Fatal("CloseRead should delegate to inner conn")
	}
}

func TestServerConn_CloseRead_Unsupported(t *testing.T) {
	inner := &mockConn{}
	sc := &serverConn{Conn: inner}
	err := sc.CloseRead()
	if err != xio.ErrUnsupported {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}

func TestServerConn_CloseWrite_Supported(t *testing.T) {
	inner := &connWithCloseWrite{Conn: &mockConn{}}
	sc := &serverConn{Conn: inner}
	if err := sc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !inner.closeWriteCalled {
		t.Fatal("CloseWrite should delegate to inner conn")
	}
}

func TestServerConn_CloseWrite_Unsupported(t *testing.T) {
	inner := &mockConn{}
	sc := &serverConn{Conn: inner}
	err := sc.CloseWrite()
	if err != xio.ErrUnsupported {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}

func TestServerConn_SyscallConn_Supported(t *testing.T) {
	inner := &connWithSyscall{Conn: &mockConn{}}
	sc := &serverConn{Conn: inner}
	_, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestServerConn_SyscallConn_Unsupported(t *testing.T) {
	inner := &mockConn{}
	sc := &serverConn{Conn: inner}
	_, err := sc.SyscallConn()
	if err != errUnsupport {
		t.Fatalf("expected errUnsupport, got %v", err)
	}
}

func TestServerConn_Context_Supported(t *testing.T) {
	inner := &connWithContext{Conn: &mockConn{}}
	sc := &serverConn{Conn: inner}
	ctx := sc.Context()
	if ctx == nil {
		t.Fatal("Context should not be nil when inner conn supports it")
	}
}

func TestServerConn_Context_Unsupported(t *testing.T) {
	inner := &mockConn{}
	sc := &serverConn{Conn: inner}
	ctx := sc.Context()
	if ctx == nil {
		t.Fatal("Context should return context.Background(), not nil")
	}
}

func TestServerConn_ReadWrite(t *testing.T) {
	inner := &mockConn{}
	sc := &serverConn{Conn: inner}

	n, err := sc.Read(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}

	n, err = sc.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("expected 5, got %d", n)
	}
}

// Ensure unused imports are fine:
var _ io.ReadWriter = (*serverConn)(nil)
var _ net.Conn = (*serverConn)(nil)
var _ = time.Now
