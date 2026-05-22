package wrapper

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/go-gost/core/admission"
	xctx "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/stretchr/testify/assert"
)

// --- WrapConn tests ---

func TestWrapConn_NilAdmission(t *testing.T) {
	c := &fakeConn{}
	result := WrapConn(nil, c)
	assert.Equal(t, c, result) // should return the original conn
}

func TestWrapConn_WithAdmission(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}}
	result := WrapConn(alwaysDenyAdmission{}, c)
	assert.IsType(t, &serverConn{}, result)
}

// --- serverConn.Read tests ---

func TestServerConn_Read_Admit(t *testing.T) {
	c := &fakeConn{
		raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data:  []byte("hello"),
	}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	buf := make([]byte, 10)
	n, err := sc.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(buf[:n]))
}

func TestServerConn_Read_Deny(t *testing.T) {
	c := &fakeConn{
		raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data:  []byte("hello"),
	}
	sc := WrapConn(alwaysDenyAdmission{}, c)
	buf := make([]byte, 10)
	n, err := sc.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

func TestServerConn_Read_AdmissionNil(t *testing.T) {
	// serverConn with nil admission should just delegate
	c := &fakeConn{
		raddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data:  []byte("hello"),
	}
	sc := &serverConn{Conn: c, admission: nil}
	buf := make([]byte, 10)
	n, err := sc.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

// --- serverConn.SyscallConn tests ---

func TestServerConn_SyscallConn_Supported(t *testing.T) {
	c := &fakeSyscallConn{fakeConn: fakeConn{raddr: &net.TCPAddr{}}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	rc, err := sc.(*serverConn).SyscallConn()
	assert.NoError(t, err)
	assert.NotNil(t, rc)
}

func TestServerConn_SyscallConn_NotSupported(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	_, err := sc.(*serverConn).SyscallConn()
	assert.Equal(t, errUnsupport, err)
}

// --- serverConn.CloseRead tests ---

func TestServerConn_CloseRead_Supported(t *testing.T) {
	c := &fakeCloseReadConn{fakeConn: fakeConn{raddr: &net.TCPAddr{}}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	err := sc.(*serverConn).CloseRead()
	assert.NoError(t, err)
}

func TestServerConn_CloseRead_NotSupported(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	err := sc.(*serverConn).CloseRead()
	assert.Equal(t, xio.ErrUnsupported, err)
}

// --- serverConn.CloseWrite tests ---

func TestServerConn_CloseWrite_Supported(t *testing.T) {
	c := &fakeCloseWriteConn{fakeConn: fakeConn{raddr: &net.TCPAddr{}}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	err := sc.(*serverConn).CloseWrite()
	assert.NoError(t, err)
}

func TestServerConn_CloseWrite_NotSupported(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	err := sc.(*serverConn).CloseWrite()
	assert.Equal(t, xio.ErrUnsupported, err)
}

// --- serverConn.Context tests ---

func TestServerConn_Context_Supported(t *testing.T) {
	testCtx := context.WithValue(context.Background(), "key", "val")
	c := &fakeContextConn{fakeConn: fakeConn{raddr: &net.TCPAddr{}}, ctx: testCtx}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	result := sc.(*serverConn).Context()
	assert.Equal(t, testCtx, result)
}

func TestServerConn_Context_NotSupported(t *testing.T) {
	// Use plainNetConn which does NOT implement xctx.Context.
	c := &plainNetConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	result := sc.(*serverConn).Context()
	assert.Nil(t, result)
}

// --- WrapPacketConn tests ---

func TestWrapPacketConn_NilAdmission(t *testing.T) {
	pc := &fakePacketConn{}
	result := WrapPacketConn(nil, pc)
	assert.Equal(t, pc, result)
}

func TestWrapPacketConn_WithAdmission(t *testing.T) {
	pc := &fakePacketConn{}
	result := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	assert.IsType(t, &packetConn{}, result)
}

// --- packetConn.ReadFrom tests ---

func TestPacketConn_ReadFrom_Admit(t *testing.T) {
	pc := &fakePacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	n, addr, err := wrapped.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

func TestPacketConn_ReadFrom_Deny(t *testing.T) {
	// The first read is denied, the second is a different address that admits.
	// But since the admission always denies, any read will loop forever.
	// We use a conn that returns error on second call.
	callCount := 0
	pc := &dynamicPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount >= 2 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	wrapped := WrapPacketConn(alwaysDenyAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, err := wrapped.ReadFrom(buf)
	assert.Equal(t, io.ErrClosedPipe, err)
	assert.Equal(t, 2, callCount)
}

func TestPacketConn_ReadFrom_Error(t *testing.T) {
	pc := &fakePacketConn{readErr: io.ErrUnexpectedEOF}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, err := wrapped.ReadFrom(buf)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

// --- packetConn.Context tests ---

func TestPacketConn_Context_Supported(t *testing.T) {
	testCtx := context.WithValue(context.Background(), "key", "val")
	pc := &fakeContextPacketConn{fakePacketConn: fakePacketConn{}, ctx: testCtx}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	result := wrapped.(*packetConn).Context()
	assert.Equal(t, testCtx, result)
}

func TestPacketConn_Context_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	result := wrapped.(*packetConn).Context()
	assert.Nil(t, result)
}

// --- WrapUDPConn tests ---

func TestWrapUDPConn(t *testing.T) {
	pc := &fakePacketConn{}
	result := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	assert.IsType(t, &udpConn{}, result)
}

// --- udpConn.RemoteAddr tests ---

func TestUDPConn_RemoteAddr_Supported(t *testing.T) {
	ra := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}
	pc := &fakeRemoteAddrPacketConn{fakePacketConn: fakePacketConn{}, raddr: ra}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	result := uc.RemoteAddr()
	assert.Equal(t, ra, result)
}

func TestUDPConn_RemoteAddr_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	result := uc.RemoteAddr()
	assert.Nil(t, result)
}

// --- udpConn.SetReadBuffer tests ---

func TestUDPConn_SetReadBuffer_Supported(t *testing.T) {
	pc := &fakeSetBufferPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	err := uc.SetReadBuffer(4096)
	assert.NoError(t, err)
}

func TestUDPConn_SetReadBuffer_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	err := uc.SetReadBuffer(4096)
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.SetWriteBuffer tests ---

func TestUDPConn_SetWriteBuffer_Supported(t *testing.T) {
	pc := &fakeSetBufferPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	err := uc.SetWriteBuffer(4096)
	assert.NoError(t, err)
}

func TestUDPConn_SetWriteBuffer_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	err := uc.SetWriteBuffer(4096)
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.Read tests ---

func TestUDPConn_Read_Supported(t *testing.T) {
	pc := &fakeReaderPacketConn{data: []byte("hello")}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	n, err := uc.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

func TestUDPConn_Read_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	_, err := uc.Read(make([]byte, 10))
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.ReadFrom tests ---

func TestUDPConn_ReadFrom_Admit(t *testing.T) {
	pc := &fakePacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	n, addr, err := uc.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

func TestUDPConn_ReadFrom_Error(t *testing.T) {
	pc := &fakePacketConn{readErr: io.ErrClosedPipe}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	_, _, err := uc.ReadFrom(make([]byte, 10))
	assert.Equal(t, io.ErrClosedPipe, err)
}

// --- udpConn.ReadFromUDP tests ---

func TestUDPConn_ReadFromUDP_Supported_Admit(t *testing.T) {
	pc := &fakeReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	n, addr, err := uc.ReadFromUDP(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

func TestUDPConn_ReadFromUDP_Supported_Deny(t *testing.T) {
	callCount := 0
	pc := &dynamicReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount >= 2 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	uc := WrapUDPConn(alwaysDenyAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, err := uc.ReadFromUDP(buf)
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestUDPConn_ReadFromUDP_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	_, _, err := uc.ReadFromUDP(make([]byte, 10))
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.ReadMsgUDP tests ---

func TestUDPConn_ReadMsgUDP_Supported_Admit(t *testing.T) {
	pc := &fakeReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	n, oobn, flags, addr, err := uc.ReadMsgUDP(buf, nil)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, 0, oobn)
	assert.Equal(t, 0, flags)
	assert.NotNil(t, addr)
}

func TestUDPConn_ReadMsgUDP_Supported_Deny(t *testing.T) {
	callCount := 0
	pc := &dynamicReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount >= 2 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	uc := WrapUDPConn(alwaysDenyAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, _, _, err := uc.ReadMsgUDP(buf, nil)
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestUDPConn_ReadMsgUDP_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	_, _, _, _, err := uc.ReadMsgUDP(make([]byte, 10), nil)
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.Write tests ---

func TestUDPConn_Write_Supported(t *testing.T) {
	pc := &fakeWriterPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	n, err := uc.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

func TestUDPConn_Write_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	_, err := uc.Write([]byte("hello"))
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.WriteTo tests ---

func TestUDPConn_WriteTo(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	n, err := uc.WriteTo([]byte("hello"), addr)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

// --- udpConn.WriteToUDP tests ---

func TestUDPConn_WriteToUDP_Supported(t *testing.T) {
	pc := &fakeWriteUDPPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	n, err := uc.WriteToUDP([]byte("hello"), addr)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

func TestUDPConn_WriteToUDP_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	_, err := uc.WriteToUDP([]byte("hello"), addr)
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.WriteMsgUDP tests ---

func TestUDPConn_WriteMsgUDP_Supported(t *testing.T) {
	pc := &fakeWriteUDPPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	n, oobn, err := uc.WriteMsgUDP([]byte("hello"), nil, addr)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, 0, oobn)
}

func TestUDPConn_WriteMsgUDP_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	_, _, err := uc.WriteMsgUDP([]byte("hello"), nil, addr)
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.SyscallConn tests ---

func TestUDPConn_SyscallConn_Supported(t *testing.T) {
	pc := &fakeSyscallPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	rc, err := uc.SyscallConn()
	assert.NoError(t, err)
	assert.NotNil(t, rc)
}

func TestUDPConn_SyscallConn_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	_, err := uc.SyscallConn()
	assert.Equal(t, errUnsupport, err)
}

// --- udpConn.SetDSCP tests ---

func TestUDPConn_SetDSCP_Supported(t *testing.T) {
	pc := &fakeSetDSCPPacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	err := uc.(*udpConn).SetDSCP(46)
	assert.NoError(t, err)
}

func TestUDPConn_SetDSCP_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	// SetDSCP returns nil on unsupported (best-effort)
	err := uc.(*udpConn).SetDSCP(46)
	assert.NoError(t, err)
}

// --- udpConn.Context tests ---

func TestUDPConn_Context_Supported(t *testing.T) {
	testCtx := context.WithValue(context.Background(), "key", "val")
	pc := &fakeContextPacketConn{fakePacketConn: fakePacketConn{}, ctx: testCtx}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	result := uc.(*udpConn).Context()
	assert.Equal(t, testCtx, result)
}

func TestUDPConn_Context_NotSupported(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	result := uc.(*udpConn).Context()
	assert.Nil(t, result)
}

// --- fake implementations for net.Conn ---

type fakeConn struct {
	raddr  net.Addr
	data   []byte
	pos    int
	ctx    context.Context
	closed bool
}

func (c *fakeConn) Read(b []byte) (n int, err error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n = copy(b, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func (c *fakeConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

// Context implements xctx.Context - returns the stored context, or background if nil.
func (c *fakeConn) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *fakeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
}

func (c *fakeConn) RemoteAddr() net.Addr {
	if c.raddr == nil {
		return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	}
	return c.raddr
}

func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error  { return nil }

// fakeSyscallConn implements syscall.Conn
type fakeSyscallConn struct {
	fakeConn
}

func (c *fakeSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return &fakeRawConn{}, nil
}

type fakeRawConn struct{}

func (r *fakeRawConn) Control(f func(fd uintptr)) error  { f(0); return nil }
func (r *fakeRawConn) Read(f func(fd uintptr) (done bool)) error { f(0); return nil }
func (r *fakeRawConn) Write(f func(fd uintptr) (done bool)) error { f(0); return nil }

// plainNetConn is a net.Conn that does NOT implement xctx.Context.
type plainNetConn struct {
	raddr net.Addr
}

func (c *plainNetConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c *plainNetConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *plainNetConn) Close() error                         { return nil }
func (c *plainNetConn) LocalAddr() net.Addr                  { return &net.TCPAddr{} }
func (c *plainNetConn) RemoteAddr() net.Addr                 { return c.raddr }
func (c *plainNetConn) SetDeadline(t time.Time) error        { return nil }
func (c *plainNetConn) SetReadDeadline(t time.Time) error    { return nil }
func (c *plainNetConn) SetWriteDeadline(t time.Time) error   { return nil }

// fakeCloseReadConn implements xio.CloseRead
type fakeCloseReadConn struct {
	fakeConn
}

func (c *fakeCloseReadConn) CloseRead() error { return nil }

// fakeCloseWriteConn implements xio.CloseWrite
type fakeCloseWriteConn struct {
	fakeConn
}

func (c *fakeCloseWriteConn) CloseWrite() error { return nil }

// fakeContextConn implements xctx.Context
type fakeContextConn struct {
	fakeConn
	ctx context.Context
}

func (c *fakeContextConn) Context() context.Context { return c.ctx }

// --- fake implementations for net.PacketConn ---

type fakePacketConn struct {
	addr    net.Addr
	data    []byte
	readErr error
}

func (pc *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if pc.readErr != nil {
		return 0, nil, pc.readErr
	}
	n = copy(p, pc.data)
	if pc.addr == nil {
		addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	} else {
		addr = pc.addr
	}
	return n, addr, nil
}

func (pc *fakePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *fakePacketConn) Close() error                       { return nil }
func (pc *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *fakePacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *fakePacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *fakePacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// dynamicPacketConn for testing deny loops
type dynamicPacketConn struct {
	addr    net.Addr
	data    []byte
	onRead  func() error
}

func (pc *dynamicPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if err := pc.onRead(); err != nil {
		return 0, nil, err
	}
	n = copy(p, pc.data)
	return n, pc.addr, nil
}

func (pc *dynamicPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *dynamicPacketConn) Close() error                       { return nil }
func (pc *dynamicPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *dynamicPacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *dynamicPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *dynamicPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// fakeReaderPacketConn implements io.Reader on top of PacketConn
type fakeReaderPacketConn struct {
	data []byte
	pos  int
}

func (pc *fakeReaderPacketConn) Read(b []byte) (n int, err error) {
	if pc.pos >= len(pc.data) {
		return 0, io.EOF
	}
	n = copy(b, pc.data[pc.pos:])
	pc.pos += n
	return n, nil
}

func (pc *fakeReaderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, io.EOF
}

func (pc *fakeReaderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *fakeReaderPacketConn) Close() error                       { return nil }
func (pc *fakeReaderPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *fakeReaderPacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *fakeReaderPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *fakeReaderPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// fakeWriterPacketConn implements io.Writer on top of PacketConn
type fakeWriterPacketConn struct{}

func (pc *fakeWriterPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, io.EOF
}

func (pc *fakeWriterPacketConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (pc *fakeWriterPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *fakeWriterPacketConn) Close() error                       { return nil }
func (pc *fakeWriterPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *fakeWriterPacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *fakeWriterPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *fakeWriterPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// fakeReadUDPPacketConn implements udp.ReadUDP
type fakeReadUDPPacketConn struct {
	addr    *net.UDPAddr
	data    []byte
	readErr error
}

func (pc *fakeReadUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if pc.readErr != nil {
		return 0, nil, pc.readErr
	}
	return copy(p, pc.data), pc.addr, nil
}

func (pc *fakeReadUDPPacketConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	if pc.readErr != nil {
		return 0, nil, pc.readErr
	}
	return copy(b, pc.data), pc.addr, nil
}

func (pc *fakeReadUDPPacketConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if pc.readErr != nil {
		return 0, 0, 0, nil, pc.readErr
	}
	return copy(b, pc.data), 0, 0, pc.addr, nil
}

func (pc *fakeReadUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *fakeReadUDPPacketConn) Close() error                       { return nil }
func (pc *fakeReadUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *fakeReadUDPPacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *fakeReadUDPPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *fakeReadUDPPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// dynamicReadUDPPacketConn for testing deny loops in ReadUDP methods
type dynamicReadUDPPacketConn struct {
	addr    *net.UDPAddr
	data    []byte
	onRead  func() error
}

func (pc *dynamicReadUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if err := pc.onRead(); err != nil {
		return 0, nil, err
	}
	return copy(p, pc.data), pc.addr, nil
}

func (pc *dynamicReadUDPPacketConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	if err := pc.onRead(); err != nil {
		return 0, nil, err
	}
	return copy(b, pc.data), pc.addr, nil
}

func (pc *dynamicReadUDPPacketConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if err := pc.onRead(); err != nil {
		return 0, 0, 0, nil, err
	}
	return copy(b, pc.data), 0, 0, pc.addr, nil
}

func (pc *dynamicReadUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *dynamicReadUDPPacketConn) Close() error                       { return nil }
func (pc *dynamicReadUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *dynamicReadUDPPacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *dynamicReadUDPPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *dynamicReadUDPPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// fakeWriteUDPPacketConn implements udp.WriteUDP
type fakeWriteUDPPacketConn struct{}

func (pc *fakeWriteUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, io.EOF
}

func (pc *fakeWriteUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (pc *fakeWriteUDPPacketConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	return len(b), nil
}

func (pc *fakeWriteUDPPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return len(b), 0, nil
}

func (pc *fakeWriteUDPPacketConn) Close() error                       { return nil }
func (pc *fakeWriteUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *fakeWriteUDPPacketConn) SetDeadline(t time.Time) error             { return nil }
func (pc *fakeWriteUDPPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (pc *fakeWriteUDPPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

// fakeRemoteAddrPacketConn implements xnet.RemoteAddr
type fakeRemoteAddrPacketConn struct {
	fakePacketConn
	raddr net.Addr
}

func (pc *fakeRemoteAddrPacketConn) RemoteAddr() net.Addr { return pc.raddr }

// fakeSetBufferPacketConn implements xnet.SetBuffer
type fakeSetBufferPacketConn struct {
	fakePacketConn
}

func (pc *fakeSetBufferPacketConn) SetReadBuffer(n int) error  { return nil }
func (pc *fakeSetBufferPacketConn) SetWriteBuffer(n int) error { return nil }

// fakeSetDSCPPacketConn implements xnet.SetDSCP
type fakeSetDSCPPacketConn struct {
	fakePacketConn
}

func (pc *fakeSetDSCPPacketConn) SetDSCP(n int) error { return nil }

// fakeSyscallPacketConn implements xnet.SyscallConn
type fakeSyscallPacketConn struct {
	fakePacketConn
}

func (pc *fakeSyscallPacketConn) SyscallConn() (syscall.RawConn, error) {
	return &fakeRawConn{}, nil
}

// fakeContextPacketConn implements xctx.Context
type fakeContextPacketConn struct {
	fakePacketConn
	ctx context.Context
}

func (pc *fakeContextPacketConn) Context() context.Context { return pc.ctx }

// --- admission helpers ---

type alwaysAdmitAdmission struct{}

func (alwaysAdmitAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	return true
}

type alwaysDenyAdmission struct{}

func (alwaysDenyAdmission) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	return false
}

// Compile-time checks
var (
	_ net.Conn      = (*fakeConn)(nil)
	_ net.PacketConn = (*fakePacketConn)(nil)
	_ io.Reader     = (*fakeReaderPacketConn)(nil)
	_ io.Writer     = (*fakeWriterPacketConn)(nil)
	_ udp.ReadUDP   = (*fakeReadUDPPacketConn)(nil)
	_ udp.WriteUDP  = (*fakeWriteUDPPacketConn)(nil)
)

// Also test that generic types compile
var (
	_ syscall.Conn    = (*fakeSyscallConn)(nil)
	_ xio.CloseRead   = (*fakeCloseReadConn)(nil)
	_ xio.CloseWrite  = (*fakeCloseWriteConn)(nil)
	_ xctx.Context    = (*fakeContextConn)(nil)
	_ xnet.SetBuffer  = (*fakeSetBufferPacketConn)(nil)
	_ xnet.SyscallConn = (*fakeSyscallPacketConn)(nil)
	_ xnet.RemoteAddr = (*fakeRemoteAddrPacketConn)(nil)
	_ xnet.SetDSCP    = (*fakeSetDSCPPacketConn)(nil)
	_ xctx.Context    = (*fakeContextPacketConn)(nil)
)

// Test that errors are handled correctly
func TestPacketConn_ReadFrom_AdmitWithNilAdmission(t *testing.T) {
	pc := &fakePacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	// packetConn with nil admission should skip admission check
	wrapped := &packetConn{PacketConn: pc, admission: nil}
	buf := make([]byte, 10)
	n, addr, err := wrapped.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

func TestUDPConn_ReadFrom_AdmitWithNilAdmission(t *testing.T) {
	pc := &fakePacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	uc := &udpConn{PacketConn: pc, admission: nil}
	buf := make([]byte, 10)
	n, addr, err := uc.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

func TestUDPConn_ReadFromUDP_NilAdmission(t *testing.T) {
	pc := &fakeReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	uc := &udpConn{PacketConn: pc, admission: nil}
	buf := make([]byte, 10)
	n, addr, err := uc.ReadFromUDP(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

func TestUDPConn_ReadMsgUDP_NilAdmission(t *testing.T) {
	pc := &fakeReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
	}
	uc := &udpConn{PacketConn: pc, admission: nil}
	buf := make([]byte, 10)
	n, _, _, addr, err := uc.ReadMsgUDP(buf, nil)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.NotNil(t, addr)
}

// Test that admission check is NOT performed on WriteTo (writes are not admission-checked)
func TestUDPConn_WriteTo_NoAdmissionCheck(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysDenyAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	n, err := uc.WriteTo([]byte("hello"), addr)
	// Should succeed even with deny admission; writes are not checked
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

// Test SetDeadline forwarding
func TestUDPConn_SetDeadline(t *testing.T) {
	pc := &fakePacketConn{}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	assert.NoError(t, uc.SetDeadline(time.Time{}))
}

// Test syscall.Conn integration via the interface
func TestServerConn_SyscallConn_Integration(t *testing.T) {
	sc := &fakeSyscallConn{fakeConn: fakeConn{raddr: &net.TCPAddr{}}}
	conn := WrapConn(alwaysAdmitAdmission{}, sc)

	// Try to access syscall.Conn via type assertion on the wrapper
	type syscallConnGetter interface {
		SyscallConn() (syscall.RawConn, error)
	}
	scc, ok := conn.(syscallConnGetter)
	assert.True(t, ok)
	rc, err := scc.SyscallConn()
	assert.NoError(t, err)
	assert.NotNil(t, rc)
}

// Test Close method forwarding
func TestServerConn_Close(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	assert.NoError(t, sc.Close())
}

// Test LocalAddr forwarding
func TestServerConn_LocalAddr(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	addr := sc.LocalAddr()
	assert.NotNil(t, addr)
}

// Test Write forwarding
func TestServerConn_Write(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	n, err := sc.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

// Test SetDeadline forwarding for serverConn
func TestServerConn_SetDeadline(t *testing.T) {
	c := &fakeConn{raddr: &net.TCPAddr{}}
	sc := WrapConn(alwaysAdmitAdmission{}, c)
	assert.NoError(t, sc.SetDeadline(time.Time{}))
	assert.NoError(t, sc.SetReadDeadline(time.Time{}))
	assert.NoError(t, sc.SetWriteDeadline(time.Time{}))
}

// Test that deny loop ReadFromUDP returns error
func TestUDPConn_ReadFromUDP_DenyLoop(t *testing.T) {
	callCount := 0
	pc := &dynamicReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount >= 3 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	uc := WrapUDPConn(alwaysDenyAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, err := uc.ReadFromUDP(buf)
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestUDPConn_ReadMsgUDP_DenyLoop(t *testing.T) {
	callCount := 0
	pc := &dynamicReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount >= 3 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	uc := WrapUDPConn(alwaysDenyAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, _, _, err := uc.ReadMsgUDP(buf, nil)
	assert.Equal(t, io.ErrClosedPipe, err)
}

// Test dynamicPacketConn deny loop with ReadFrom (same as ReadFromUDP flow)
func TestUDPConn_ReadFrom_DenyLoop(t *testing.T) {
	callCount := 0
	pc := &dynamicPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount >= 3 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	uc := WrapUDPConn(alwaysDenyAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, err := uc.ReadFrom(buf)
	assert.Equal(t, io.ErrClosedPipe, err)
}

// Test ReadFromUDP returns error on first read
func TestUDPConn_ReadFromUDP_ReadError(t *testing.T) {
	pc := &fakeReadUDPPacketConn{
		readErr: errors.New("custom error"),
	}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, err := uc.ReadFromUDP(buf)
	assert.EqualError(t, err, "custom error")
}

// Test ReadMsgUDP returns error on first read
func TestUDPConn_ReadMsgUDP_ReadError(t *testing.T) {
	pc := &fakeReadUDPPacketConn{
		readErr: errors.New("custom error"),
	}
	uc := WrapUDPConn(alwaysAdmitAdmission{}, pc)
	buf := make([]byte, 10)
	_, _, _, _, err := uc.ReadMsgUDP(buf, nil)
	assert.EqualError(t, err, "custom error")
}

// Test ReadFromUDP with admit but no nil admission check (since WrapUDPConn always sets admission)
func TestUDPConn_ReadFromUDP_AdmitDenyLoopCoverage(t *testing.T) {
	callCount := 0
	pc := &dynamicReadUDPPacketConn{
		addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
		data: []byte("hello"),
		onRead: func() error {
			callCount++
			if callCount > 5 {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	uc := &udpConn{PacketConn: pc, admission: alwaysDenyAdmission{}}
	buf := make([]byte, 10)
	_, _, err := uc.ReadFromUDP(buf)
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestPacketConn_Close(t *testing.T) {
	pc := &fakePacketConn{}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	assert.NoError(t, wrapped.Close())
}

func TestPacketConn_LocalAddr(t *testing.T) {
	pc := &fakePacketConn{}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	addr := wrapped.LocalAddr()
	assert.NotNil(t, addr)
}

func TestPacketConn_SetDeadline(t *testing.T) {
	pc := &fakePacketConn{}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	assert.NoError(t, wrapped.SetDeadline(time.Time{}))
	assert.NoError(t, wrapped.SetReadDeadline(time.Time{}))
	assert.NoError(t, wrapped.SetWriteDeadline(time.Time{}))
}

func TestPacketConn_WriteTo(t *testing.T) {
	pc := &fakePacketConn{}
	wrapped := WrapPacketConn(alwaysAdmitAdmission{}, pc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	n, err := wrapped.WriteTo([]byte("hello"), addr)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}
