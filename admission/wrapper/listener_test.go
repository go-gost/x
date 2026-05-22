package wrapper

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/go-gost/core/admission"
	xctx "github.com/go-gost/x/ctx"
	"github.com/stretchr/testify/assert"
)

// --- WrapListener tests ---

func TestWrapListener_NilAdmission(t *testing.T) {
	ln := &fakeListener{}
	result := WrapListener("myservice", nil, ln)
	assert.Equal(t, ln, result) // should return the original listener
}

func TestWrapListener_WithAdmission(t *testing.T) {
	ln := &fakeListener{}
	result := WrapListener("myservice", alwaysAdmitAdmission{}, ln)
	assert.IsType(t, &listener{}, result)
}

// --- listener.Accept tests ---

func TestListener_Accept_Admit(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}}
	ln := &fakeListener{conns: []net.Conn{c}}
	wrapped := WrapListener("myservice", alwaysAdmitAdmission{}, ln)

	conn, err := wrapped.Accept()
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.False(t, c.closed)
}

func TestListener_Accept_Deny(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}}
	denied := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5678}}
	ln := &fakeListener{conns: []net.Conn{denied, c}}
	wrapped := WrapListener("myservice", &denyFirstConnAdmission{}, ln)

	// First connection is denied, second is admitted
	conn, err := wrapped.Accept()
	assert.NoError(t, err)
	assert.Equal(t, c, conn)
	assert.True(t, denied.closed)
}

func TestListener_Accept_Error(t *testing.T) {
	ln := &fakeListener{acceptErr: errors.New("accept failed")}
	wrapped := WrapListener("myservice", alwaysAdmitAdmission{}, ln)

	_, err := wrapped.Accept()
	assert.EqualError(t, err, "accept failed")
}

func TestListener_Accept_WithContextSrcAddr(t *testing.T) {
	srcAddr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1234}
	c := &fakeConn{
		raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		ctx:   xctx.ContextWithSrcAddr(context.Background(), srcAddr),
	}
	ln := &fakeListener{conns: []net.Conn{c}}

	// Use an admission that records the address it receives
	recorder := &recordingAdmission{admit: true}
	wrapped := WrapListener("myservice", recorder, ln)

	conn, err := wrapped.Accept()
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	// Should have used the src addr from context (String() includes port)
	assert.Equal(t, "1.2.3.4:1234", recorder.lastAddr)
}

func TestListener_Accept_WithContextNilContext(t *testing.T) {
	c := &fakeConn{
		raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		ctx:   nil, // returns nil context
	}
	ln := &fakeListener{conns: []net.Conn{c}}

	recorder := &recordingAdmission{admit: true}
	wrapped := WrapListener("myservice", recorder, ln)

	conn, err := wrapped.Accept()
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	// Should fall back to RemoteAddr (String() includes port)
	assert.Equal(t, "192.168.1.1:1234", recorder.lastAddr)
}

func TestListener_Accept_NoContextInterface(t *testing.T) {
	// A plain net.Conn without xctx.Context support
	c := &plainNetConn{raddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}}
	ln := &fakeListener{conns: []net.Conn{c}}

	recorder := &recordingAdmission{admit: true}
	wrapped := WrapListener("myservice", recorder, ln)

	conn, err := wrapped.Accept()
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	// Should use RemoteAddr (String() includes port)
	assert.Equal(t, "10.0.0.1:9999", recorder.lastAddr)
}

func TestListener_Accept_MultipleDeniesThenAdmit(t *testing.T) {
	denied1 := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}}
	denied2 := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2}}
	admitted := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 3}}
	ln := &fakeListener{conns: []net.Conn{denied1, denied2, admitted}}

	// Deny the first two, admit the third
	count := 0
	conditional := &conditionalAdmission{
		fn: func(ctx context.Context, network, addr string, opts ...admission.Option) bool {
			count++
			return count > 2
		},
	}
	wrapped := WrapListener("myservice", conditional, ln)

	conn, err := wrapped.Accept()
	assert.NoError(t, err)
	assert.Equal(t, admitted, conn)
	assert.True(t, denied1.closed)
	assert.True(t, denied2.closed)
	assert.False(t, admitted.closed)
}

// Test that Close is forwarded to the underlying listener
func TestListener_Close(t *testing.T) {
	ln := &fakeListener{}
	wrapped := WrapListener("myservice", alwaysAdmitAdmission{}, ln)
	err := wrapped.Close()
	assert.NoError(t, err)
	assert.True(t, ln.closed)
}

// Test that Addr is forwarded to the underlying listener
func TestListener_Addr(t *testing.T) {
	ln := &fakeListener{}
	wrapped := WrapListener("myservice", alwaysAdmitAdmission{}, ln)
	addr := wrapped.Addr()
	assert.NotNil(t, addr)
}

// --- fake types for listener tests ---

type fakeListener struct {
	conns     []net.Conn
	pos       int
	acceptErr error
	closed    bool
}

func (ln *fakeListener) Accept() (net.Conn, error) {
	if ln.acceptErr != nil {
		return nil, ln.acceptErr
	}
	if ln.pos >= len(ln.conns) {
		return nil, errors.New("no more connections")
	}
	c := ln.conns[ln.pos]
	ln.pos++
	return c, nil
}

func (ln *fakeListener) Close() error {
	ln.closed = true
	return nil
}

func (ln *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

// --- admission helpers for listener tests ---

type recordingAdmission struct {
	admit    bool
	lastAddr string
}

func (r *recordingAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	r.lastAddr = addr
	return r.admit
}

type denyFirstConnAdmission struct {
	count int
}

func (d *denyFirstConnAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	d.count++
	return d.count > 1 // deny first, admit rest
}

type conditionalAdmission struct {
	fn func(ctx context.Context, network, addr string, opts ...admission.Option) bool
}

func (c *conditionalAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	return c.fn(ctx, network, addr, opts...)
}

// Compile-time checks
var (
	_ net.Listener = (*fakeListener)(nil)
	_ net.Conn     = (*fakeConn)(nil)
	_ xctx.Context = (*fakeConn)(nil)
	_ net.Conn     = (*plainNetConn)(nil)
)

// Test that plainNetConn does NOT implement xctx.Context
func TestPlainNetConn_NoContext(t *testing.T) {
	c := &plainNetConn{raddr: &net.TCPAddr{}}
	_, ok := any(c).(xctx.Context)
	assert.False(t, ok)
}

// Test that fakeConn DOES implement xctx.Context
func TestFakeConn_HasContext(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	_, ok := any(c).(xctx.Context)
	assert.True(t, ok)
}

