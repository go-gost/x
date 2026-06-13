package wrapper

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/x/internal/net/udp"
	ostats "github.com/go-gost/x/observer/stats"
)

// --- mock types ---

type fakeConn struct {
	net.Conn
	readBuf   []byte
	readPos   int
	writeBuf  []byte
	closed    bool
	syscallFn func() (syscall.RawConn, error)
}

func (c *fakeConn) Read(b []byte) (int, error) {
	if c.readPos >= len(c.readBuf) {
		return 0, errors.New("EOF")
	}
	n := copy(b, c.readBuf[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *fakeConn) Write(b []byte) (int, error) {
	c.writeBuf = append(c.writeBuf, b...)
	return len(b), nil
}

func (c *fakeConn) Close() error {
	if c.closed {
		return errors.New("already closed")
	}
	c.closed = true
	return nil
}

type fakePacketConn struct {
	readBuf  []byte
	readPos  int
	writeBuf []byte
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readPos >= len(c.readBuf) {
		return 0, nil, errors.New("EOF")
	}
	n := copy(p, c.readBuf[c.readPos:])
	c.readPos += n
	return n, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1234}, nil
}

func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeBuf = append(c.writeBuf, p...)
	return len(p), nil
}

func (c *fakePacketConn) Close() error { return nil }

func (c *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
}

func (c *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// --- WrapConn tests ---

func TestWrapConn_Nil(t *testing.T) {
	// nil conn
	if result := WrapConn(nil, ostats.NewStats(false)); result != nil {
		t.Error("WrapConn with nil conn should return nil")
	}
	// nil stats
	fc := &fakeConn{}
	if result := WrapConn(fc, nil); result != fc {
		t.Error("WrapConn with nil stats should return original conn")
	}
	// both nil
	if result := WrapConn(nil, nil); result != nil {
		t.Error("WrapConn with both nil should return nil")
	}
}

func TestWrapConn_IncrementsCounters(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	WrapConn(fc, st)

	if v := st.Get(stats.KindTotalConns); v != 1 {
		t.Errorf("totalConns = %d, want 1", v)
	}
	if v := st.Get(stats.KindCurrentConns); v != 1 {
		t.Errorf("currentConns = %d, want 1", v)
	}
}

func TestWrapConn_ReadWrite(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{readBuf: []byte("hello")}
	wrapped := WrapConn(fc, st)

	buf := make([]byte, 10)
	n, _ := wrapped.Read(buf)
	if n != 5 {
		t.Fatalf("read n = %d, want 5", n)
	}
	if v := st.Get(stats.KindInputBytes); v != 5 {
		t.Errorf("inputBytes = %d, want 5", v)
	}

	n, _ = wrapped.Write([]byte("world"))
	if n != 5 {
		t.Fatalf("write n = %d, want 5", n)
	}
	if v := st.Get(stats.KindOutputBytes); v != 5 {
		t.Errorf("outputBytes = %d, want 5", v)
	}
}

func TestWrapConn_Close(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	// currentConns should be 1 after wrap
	if v := st.Get(stats.KindCurrentConns); v != 1 {
		t.Fatalf("currentConns = %d, want 1", v)
	}

	wrapped.Close()

	if v := st.Get(stats.KindCurrentConns); v != 0 {
		t.Errorf("currentConns after close = %d, want 0", v)
	}
	if !fc.closed {
		t.Error("underlying conn should be closed")
	}
}

func TestWrapConn_DoubleClose(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	wrapped.Close()
	wrapped.Close() // must not panic and must not double-decrement

	if v := st.Get(stats.KindCurrentConns); v != 0 {
		t.Errorf("currentConns = %d after double close, want 0", v)
	}
}

func TestWrapConn_CloseRace(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	done := make(chan struct{})
	go func() {
		wrapped.Close()
		done <- struct{}{}
	}()
	go func() {
		wrapped.Close()
		done <- struct{}{}
	}()
	<-done
	<-done

	// currentConns should only be decremented once
	if v := st.Get(stats.KindCurrentConns); v != 0 {
		t.Errorf("currentConns after concurrent close = %d, want 0", v)
	}
}

func TestWrapConn_CloseRead(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	err := wrapped.(*conn).CloseRead()
	if err == nil {
		t.Error("CloseRead on basic conn should return error")
	}
}

func TestWrapConn_CloseWrite(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	err := wrapped.(*conn).CloseWrite()
	if err == nil {
		t.Error("CloseWrite on basic conn should return error")
	}
}

func TestWrapConn_SyscallConn(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	_, err := wrapped.(*conn).SyscallConn()
	if err == nil {
		t.Error("SyscallConn on non-syscall conn should return error")
	}
}

func TestWrapConn_Context(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	wrapped := WrapConn(fc, st)

	if wrapped.(*conn).Context() != nil {
		t.Error("Context on basic conn should return nil")
	}
}

// --- WrapPacketConn tests ---

func TestWrapPacketConn_Nil(t *testing.T) {
	// nil pc
	if result := WrapPacketConn(nil, ostats.NewStats(false)); result != nil {
		t.Error("WrapPacketConn with nil pc should return nil")
	}
	// nil stats
	fpc := &fakePacketConn{}
	if result := WrapPacketConn(fpc, nil); result != fpc {
		t.Error("WrapPacketConn with nil stats should return original conn")
	}
	// both nil
	if result := WrapPacketConn(nil, nil); result != nil {
		t.Error("WrapPacketConn with both nil should return nil")
	}
}

func TestWrapPacketConn_ReadFrom(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{readBuf: []byte("packet-data")}
	wrapped := WrapPacketConn(fpc, st)

	buf := make([]byte, 32)
	n, addr, err := wrapped.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Fatalf("n = %d, want 11", n)
	}
	if addr == nil {
		t.Fatal("addr should not be nil")
	}
	if v := st.Get(stats.KindInputBytes); v != 11 {
		t.Errorf("inputBytes = %d, want 11", v)
	}
}

func TestWrapPacketConn_WriteTo(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapPacketConn(fpc, st)

	addr := &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 5678}
	n, err := wrapped.WriteTo([]byte("hello"), addr)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if v := st.Get(stats.KindOutputBytes); v != 5 {
		t.Errorf("outputBytes = %d, want 5", v)
	}
}

func TestWrapPacketConn_Context(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapPacketConn(fpc, st)

	if wrapped.(*packetConn).Context() != nil {
		t.Error("Context should return nil for basic packet conn")
	}
}

// --- WrapUDPConn tests ---

func TestWrapUDPConn_Nil(t *testing.T) {
	if result := WrapUDPConn(nil, ostats.NewStats(false)); result != nil {
		t.Error("WrapUDPConn with nil pc should return nil")
	}
	if result := WrapUDPConn(&fakePacketConn{}, nil); result != nil {
		t.Error("WrapUDPConn with nil stats should return nil")
	}
}

func TestWrapUDPConn_Conns(t *testing.T) {
	st := ostats.NewStats(false)
	WrapUDPConn(&fakePacketConn{}, st)

	if v := st.Get(stats.KindTotalConns); v != 1 {
		t.Errorf("totalConns = %d, want 1", v)
	}
	if v := st.Get(stats.KindCurrentConns); v != 1 {
		t.Errorf("currentConns = %d, want 1", v)
	}
}

func TestWrapUDPConn_Close(t *testing.T) {
	st := ostats.NewStats(false)
	wrapped := WrapUDPConn(&fakePacketConn{}, st)

	if err := wrapped.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if v := st.Get(stats.KindCurrentConns); v != 0 {
		t.Errorf("currentConns after close = %d, want 0", v)
	}

	// A second Close must be a no-op: currentConns must not go negative.
	if err := wrapped.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if v := st.Get(stats.KindCurrentConns); v != 0 {
		t.Errorf("currentConns after second close = %d, want 0", v)
	}
	if v := st.Get(stats.KindTotalConns); v != 1 {
		t.Errorf("totalConns = %d, want 1 (monotonic)", v)
	}
}

func TestWrapUDPConn_ReadFrom(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{readBuf: []byte("udp-packet")}
	wrapped := WrapUDPConn(fpc, st)

	buf := make([]byte, 32)
	n, _, err := wrapped.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("n = %d, want 10", n)
	}
	if v := st.Get(stats.KindInputBytes); v != 10 {
		t.Errorf("inputBytes = %d, want 10", v)
	}
}

func TestWrapUDPConn_WriteTo(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	addr := &net.UDPAddr{IP: net.IPv4(3, 3, 3, 3), Port: 4444}
	n, err := wrapped.WriteTo([]byte("data"), addr)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("n = %d, want 4", n)
	}
	if v := st.Get(stats.KindOutputBytes); v != 4 {
		t.Errorf("outputBytes = %d, want 4", v)
	}
}

func TestWrapUDPConn_RemoteAddr(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	// fakePacketConn doesn't implement xnet.RemoteAddr, so this returns nil
	if wrapped.RemoteAddr() != nil {
		t.Error("RemoteAddr should return nil for basic packet conn")
	}
}

func TestWrapUDPConn_SetReadBuffer(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	err := wrapped.SetReadBuffer(4096)
	if err == nil {
		t.Error("SetReadBuffer should return error for basic packet conn")
	}
}

func TestWrapUDPConn_SetWriteBuffer(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	err := wrapped.SetWriteBuffer(4096)
	if err == nil {
		t.Error("SetWriteBuffer should return error for basic packet conn")
	}
}

func TestWrapUDPConn_SetDSCP(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	// fakePacketConn doesn't implement xnet.SetDSCP, so this returns nil
	uc := wrapped.(*udpConn)
	if err := uc.SetDSCP(46); err != nil {
		t.Errorf("SetDSCP should return nil, got %v", err)
	}
}

func TestWrapUDPConn_SyscallConn(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	_, err := wrapped.SyscallConn()
	if err == nil {
		t.Error("SyscallConn should return error for basic packet conn")
	}
}

func TestWrapUDPConn_Context(t *testing.T) {
	st := ostats.NewStats(false)
	fpc := &fakePacketConn{}
	wrapped := WrapUDPConn(fpc, st)

	uc := wrapped.(*udpConn)
	if uc.Context() != nil {
		t.Error("Context should return nil for basic packet conn")
	}
}

// Verify the returned types are correct
func TestWrapConn_ReturnType(t *testing.T) {
	fc := &fakeConn{}
	st := ostats.NewStats(false)
	result := WrapConn(fc, st)
	if _, ok := result.(*conn); !ok {
		t.Errorf("WrapConn returned %T, want *conn", result)
	}
}

func TestWrapPacketConn_ReturnType(t *testing.T) {
	fpc := &fakePacketConn{}
	st := ostats.NewStats(false)
	result := WrapPacketConn(fpc, st)
	if _, ok := result.(*packetConn); !ok {
		t.Errorf("WrapPacketConn returned %T, want *packetConn", result)
	}
}

func TestWrapUDPConn_ReturnType(t *testing.T) {
	fpc := &fakePacketConn{}
	st := ostats.NewStats(false)
	result := WrapUDPConn(fpc, st)
	if _, ok := result.(*udpConn); !ok {
		t.Errorf("WrapUDPConn returned %T, want *udpConn", result)
	}
}

// Ensure the wrapper satisfies udp.Conn
var _ udp.Conn = &udpConn{}
