package wrapper

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	xio "github.com/go-gost/x/internal/io"
	ctxutil "github.com/go-gost/x/ctx"
)

// --- mock types ---

type mockLimiter struct {
	waitFunc func(ctx context.Context, n int) int
	limit    int
}

func (m *mockLimiter) Wait(ctx context.Context, n int) int {
	if m.waitFunc != nil {
		return m.waitFunc(ctx, n)
	}
	return n
}
func (m *mockLimiter) Limit() int { return m.limit }
func (m *mockLimiter) Set(n int)  { m.limit = n }

type mockTrafficLimiter struct {
	inLim  traffic.Limiter
	outLim traffic.Limiter
}

func (m *mockTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return m.inLim
}
func (m *mockTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return m.outLim
}

// --- WrapConn tests ---

func TestWrapConn_NilLimiter(t *testing.T) {
	c := &struct{ net.Conn }{}
	result := WrapConn(c, nil, "key")
	if result != c {
		t.Fatal("nil limiter should return original conn")
	}
}

func TestWrapConn_WithLimiter(t *testing.T) {
	c := &struct{ net.Conn }{}
	tl := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	result := WrapConn(c, tl, "key")
	lc, ok := result.(*limitConn)
	if !ok {
		t.Fatalf("expected *limitConn, got %T", result)
	}
	if lc.Conn != c {
		t.Fatal("wrapped conn should retain inner conn")
	}
}

func TestLimitConn_Read_NoLimiter(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tl := &mockTrafficLimiter{inLim: nil}
	wrapped := WrapConn(client, tl, "test-key")

	go server.Write([]byte("hello"))

	buf := make([]byte, 10)
	n, err := wrapped.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:5]) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestLimitConn_Read_WithLimiter(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ml := &mockLimiter{limit: 100}
	tl := &mockTrafficLimiter{inLim: ml}
	wrapped := WrapConn(client, tl, "test-key")

	go func() {
		server.Write([]byte("hello world"))
		server.Close()
	}()

	buf := make([]byte, 100)
	n, err := wrapped.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(buf[:n]))
	}
}

func TestLimitConn_Read_BufferedData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	callCount := 0
	ml := &mockLimiter{
		limit: 100,
		waitFunc: func(ctx context.Context, n int) int {
			callCount++
			if callCount == 1 {
				return 5 // only allow 5 of 11 bytes
			}
			return 10
		},
	}
	tl := &mockTrafficLimiter{inLim: ml}
	wrapped := WrapConn(client, tl, "test-key")

	go func() {
		server.Write([]byte("hello world"))
		server.Close()
	}()

	buf := make([]byte, 100)
	n, err := readFull(wrapped, buf, 5)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes, got %d", n)
	}

	// Remaining bytes from rbuf.
	n, err = readFull(wrapped, buf[5:], 6)
	if err != nil {
		t.Fatalf("second read (buffered): %v", err)
	}
	if n != 6 {
		t.Fatalf("expected 6 buffered bytes, got %d", n)
	}
}

func TestLimitConn_Write_NoLimiter(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tl := &mockTrafficLimiter{outLim: nil}
	wrapped := WrapConn(client, tl, "test-key")

	go func() {
		buf := make([]byte, 5)
		server.Read(buf)
	}()

	n, err := wrapped.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("expected 5, got %d", n)
	}
}

func TestLimitConn_Write_ZeroBurst(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ml := &mockLimiter{
		limit: 100,
		waitFunc: func(ctx context.Context, n int) int {
			return 0
		},
	}
	tl := &mockTrafficLimiter{outLim: ml}
	wrapped := WrapConn(client, tl, "test-key")

	n, err := wrapped.Write([]byte("data"))
	if err != nil {
		t.Fatalf("should not error on zero burst: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

type connWithSyscall struct {
	net.Conn
}

func (c *connWithSyscall) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}

func TestLimitConn_SyscallConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	c := &connWithSyscall{Conn: client}
	tl := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	wrapped := WrapConn(c, tl, "test-key")

	_, err := wrapped.(*limitConn).SyscallConn()
	if err != nil {
		t.Fatal("SyscallConn should succeed", err)
	}
}

type connWithCloseRead struct {
	net.Conn
	closed bool
}

func (c *connWithCloseRead) CloseRead() error {
	c.closed = true
	return nil
}

func TestLimitConn_CloseRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	c := &connWithCloseRead{Conn: client}
	tl := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	wrapped := WrapConn(c, tl, "test-key")

	lc := wrapped.(*limitConn)
	if err := lc.CloseRead(); err != nil {
		t.Fatal("CloseRead should succeed", err)
	}
	if !c.closed {
		t.Fatal("CloseRead should delegate to inner")
	}
}

type connWithCloseWrite struct {
	net.Conn
	closed bool
}

func (c *connWithCloseWrite) CloseWrite() error {
	c.closed = true
	return nil
}

func TestLimitConn_CloseWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	c := &connWithCloseWrite{Conn: client}
	tl := &mockTrafficLimiter{inLim: &mockLimiter{limit: 100}}
	wrapped := WrapConn(c, tl, "test-key")

	lc := wrapped.(*limitConn)
	if err := lc.CloseWrite(); err != nil {
		t.Fatal("CloseWrite should succeed", err)
	}
	if !c.closed {
		t.Fatal("CloseWrite should delegate to inner")
	}
}

// --- WrapReadWriter tests ---

func TestWrapReadWriter_NilLimiter(t *testing.T) {
	rw := &bytesReadWriter{}
	result := WrapReadWriter(nil, rw, "key")
	if result != rw {
		t.Fatal("nil limiter should return original ReadWriter")
	}
}

func TestReadWriter_Read_WithLimiter(t *testing.T) {
	data := []byte("hello world")
	rw := &bytesReadWriter{buf: append([]byte{}, data...)}

	ml := &mockLimiter{limit: 100}
	tl := &mockTrafficLimiter{inLim: ml}
	wrapped := WrapReadWriter(tl, rw, "test-key")

	buf := make([]byte, 100)
	n, err := wrapped.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(buf[:n]))
	}
}

func TestReadWriter_Write_ZeroBurst(t *testing.T) {
	rw := &bytesReadWriter{}
	ml := &mockLimiter{
		limit: 100,
		waitFunc: func(ctx context.Context, n int) int {
			return 0
		},
	}
	tl := &mockTrafficLimiter{outLim: ml}
	wrapped := WrapReadWriter(tl, rw, "test-key")

	n, err := wrapped.Write([]byte("data"))
	if err != nil {
		t.Fatalf("should not error on zero burst: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

// --- WrapPacketConn tests ---

func TestWrapPacketConn_NilLimiter(t *testing.T) {
	pc := &struct{ net.PacketConn }{}
	result := WrapPacketConn(pc, nil, "key")
	if result != pc {
		t.Fatal("nil limiter should return original PacketConn")
	}
}

func TestPacketConn_WriteTo_RateLimited(t *testing.T) {
	pc := &mockPacketConn{writeBuf: make([]byte, 100)}
	ml := &mockLimiter{
		limit: 100,
		waitFunc: func(ctx context.Context, n int) int {
			return 3 // allow only 3, but packet is 4 bytes
		},
	}
	tl := &mockTrafficLimiter{outLim: ml}
	wrapped := WrapPacketConn(pc, tl, "test-key")

	_, err := wrapped.WriteTo([]byte("data"), nil)
	if !errors.Is(err, errRateLimited) {
		t.Fatalf("expected errRateLimited, got %v", err)
	}
}

// --- WrapUDPConn tests ---

func TestWrapUDPConn(t *testing.T) {
	pc := &mockPacketConn{writeBuf: make([]byte, 100)}
	result := WrapUDPConn(pc, &mockTrafficLimiter{}, "key")
	if _, ok := result.(*udpConn); !ok {
		t.Fatalf("expected *udpConn, got %T", result)
	}
}

func TestPacketConn_DroppedPackets(t *testing.T) {
	pc := &mockPacketConn{writeBuf: make([]byte, 100)}
	calls := 0
	pc.readFromFunc = func(p []byte) (int, net.Addr, error) {
		calls++
		if calls == 1 {
			return copy(p, "data-4"), nil, nil // 6 bytes, limiter allows 5 = drop
		}
		return copy(p, "ok"), nil, nil // 2 bytes, limiter allows 5 = pass
	}
	ml := &mockLimiter{
		limit: 100,
		waitFunc: func(ctx context.Context, n int) int {
			return 5 // allow 5 bytes; 6-byte packet is dropped, 2-byte passes
		},
	}
	tl := &mockTrafficLimiter{inLim: ml}
	wrapped := WrapPacketConn(pc, tl, "test-key")

	_, _, err := wrapped.ReadFrom(make([]byte, 10))
	if err != nil {
		t.Fatal(err)
	}
	counter := wrapped.(DroppedPacketCounter)
	if n := counter.DroppedPackets(); n != 1 {
		t.Fatalf("expected 1 dropped packet, got %d", n)
	}
}

func TestUDPConn_Write_RateLimited(t *testing.T) {
	pc := &mockPacketConn{writeBuf: make([]byte, 100)}
	ml := &mockLimiter{
		limit: 100,
		waitFunc: func(ctx context.Context, n int) int {
			return 2 // allow fewer bytes than packet
		},
	}
	tl := &mockTrafficLimiter{outLim: ml}
	wrapped := WrapUDPConn(pc, tl, "test-key")

	_, err := wrapped.Write([]byte("dat"))
	if !errors.Is(err, errRateLimited) {
		t.Fatalf("expected errRateLimited, got %v", err)
	}
}

// --- interface compliance ---

var (
	_ net.Conn     = (*limitConn)(nil)
	_ net.Conn     = (*struct{ net.Conn })(nil)
	_ xio.CloseRead  = (*limitConn)(nil)
	_ xio.CloseWrite = (*limitConn)(nil)
	_ syscall.Conn   = (*limitConn)(nil)
	_ ctxutil.Context = (*limitConn)(nil)

	_ DroppedPacketCounter = (*packetConn)(nil)
	_ DroppedPacketCounter = (*udpConn)(nil)
)

// --- helpers ---

type bytesReadWriter struct {
	buf []byte
}

func (rw *bytesReadWriter) Read(b []byte) (int, error) {
	if len(rw.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(b, rw.buf)
	rw.buf = rw.buf[n:]
	return n, nil
}

func (rw *bytesReadWriter) Write(b []byte) (int, error) {
	rw.buf = append(rw.buf, b...)
	return len(b), nil
}

type mockPacketConn struct {
	net.PacketConn
	writeBuf     []byte
	readFromFunc func(p []byte) (int, net.Addr, error)
}

func (pc *mockPacketConn) Write(p []byte) (int, error) {
	pc.writeBuf = append(pc.writeBuf[:0], p...)
	return len(p), nil
}

func (pc *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pc.writeBuf = append(pc.writeBuf[:0], p...)
	return len(p), nil
}

func (pc *mockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if pc.readFromFunc != nil {
		return pc.readFromFunc(p)
	}
	return copy(p, "test"), nil, nil
}

func (pc *mockPacketConn) Close() error                       { return nil }
func (pc *mockPacketConn) LocalAddr() net.Addr                { return nil }
func (pc *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (pc *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (pc *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func readFull(c net.Conn, buf []byte, want int) (int, error) {
	total := 0
	for total < want {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
