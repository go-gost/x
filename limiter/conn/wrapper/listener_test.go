package wrapper

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	limiter "github.com/go-gost/core/limiter/conn"
)

type mockConn struct {
	closed bool
}

func (c *mockConn) Read(b []byte) (int, error)         { return 0, nil }
func (c *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *mockConn) Close() error                       { c.closed = true; return nil }
func (c *mockConn) LocalAddr() net.Addr                { return nil }
func (c *mockConn) RemoteAddr() net.Addr               { return &mockAddr{addr: "192.168.1.1:1234"} }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr struct {
	addr string
}

func (a *mockAddr) Network() string { return "tcp" }
func (a *mockAddr) String() string  { return a.addr }

type mockListener struct {
	conns   []net.Conn
	current int
}

func (l *mockListener) Accept() (net.Conn, error) {
	if l.current >= len(l.conns) {
		return nil, errors.New("no more conns")
	}
	c := l.conns[l.current]
	l.current++
	return c, nil
}

func (l *mockListener) Close() error   { return nil }
func (l *mockListener) Addr() net.Addr { return nil }

type allowLimiter struct {
	limit int
	count int
}

func (l *allowLimiter) Allow(n int) bool {
	if l.count+n > l.limit {
		return false
	}
	l.count += n
	return true
}
func (l *allowLimiter) Limit() int { return l.limit }

type connLimiter struct {
	lims map[string]limiter.Limiter
}

func (cl *connLimiter) Limiter(key string) limiter.Limiter {
	return cl.lims[key]
}

func TestWrapListener_NilLimiter(t *testing.T) {
	inner := &mockListener{}
	ln := WrapListener(nil, inner)
	if ln != inner {
		t.Fatal("WrapListener should return the inner listener when limiter is nil")
	}
}

func TestAccept_NoLimiterForKey(t *testing.T) {
	inner := &mockListener{conns: []net.Conn{&mockConn{}}}
	cl := &connLimiter{lims: map[string]limiter.Limiter{}}
	ln := WrapListener(cl, inner)

	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("conn should not be nil")
	}
}

func TestAccept_AllowSuccess(t *testing.T) {
	inner := &mockListener{conns: []net.Conn{&mockConn{}}}
	cl := &connLimiter{lims: map[string]limiter.Limiter{
		"192.168.1.1": &allowLimiter{limit: 1},
	}}
	ln := WrapListener(cl, inner)

	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("conn should not be nil")
	}

	// Should be wrapped in serverConn.
	if _, ok := c.(*serverConn); !ok {
		t.Fatal("conn should be wrapped as *serverConn")
	}
}

func TestAccept_LimitExceeded(t *testing.T) {
	mc := &mockConn{}
	inner := &mockListener{conns: []net.Conn{mc}}
	cl := &connLimiter{lims: map[string]limiter.Limiter{
		"192.168.1.1": &allowLimiter{limit: 0}, // always deny
	}}
	ln := WrapListener(cl, inner)

	c, err := ln.Accept()
	if err == nil {
		t.Fatal("expected error when limit exceeded")
	}
	if !strings.Contains(err.Error(), "limit exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("conn should be nil when limit exceeded")
	}
	if !mc.closed {
		t.Fatal("conn should be closed when rejected")
	}
}

func TestAccept_ListenerError(t *testing.T) {
	inner := &mockListener{} // no conns, Accept returns error
	cl := &connLimiter{lims: map[string]limiter.Limiter{}}
	ln := WrapListener(cl, inner)

	_, err := ln.Accept()
	if err == nil {
		t.Fatal("expected error from listener")
	}
}
