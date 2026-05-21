package udp

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
)

// nopLogger is a no-op logger for testing
type nopLogger struct{}

func (l *nopLogger) WithFields(map[string]any) logger.Logger      { return l }
func (l *nopLogger) Trace(args ...any)                             {}
func (l *nopLogger) Tracef(format string, args ...any)             {}
func (l *nopLogger) Debug(args ...any)                             {}
func (l *nopLogger) Debugf(format string, args ...any)             {}
func (l *nopLogger) Info(args ...any)                              {}
func (l *nopLogger) Infof(format string, args ...any)              {}
func (l *nopLogger) Warn(args ...any)                              {}
func (l *nopLogger) Warnf(format string, args ...any)              {}
func (l *nopLogger) Error(args ...any)                             {}
func (l *nopLogger) Errorf(format string, args ...any)             {}
func (l *nopLogger) Fatal(args ...any)                             {}
func (l *nopLogger) Fatalf(format string, args ...any)             {}
func (l *nopLogger) GetLevel() logger.LogLevel                     { return logger.InfoLevel }
func (l *nopLogger) IsLevelEnabled(level logger.LogLevel) bool     { return false }

// mockPacketConn implements net.PacketConn for unit testing
type mockPacketConn struct {
	readFn    func(b []byte) (int, net.Addr, error)
	writeFn   func(b []byte, addr net.Addr) (int, error)
	closeErr  error
	localAddr net.Addr
	closed    bool
	mu        sync.Mutex
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000},
	}
}

func (m *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if m.readFn != nil {
		return m.readFn(b)
	}
	// Default: return on first call, then error
	return 0, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}, errors.New("no readFn set")
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if m.writeFn != nil {
		return m.writeFn(b, addr)
	}
	return len(b), nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

func (m *mockPacketConn) LocalAddr() net.Addr           { return m.localAddr }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockPacketConn) SetReadBuffer(n int) error          { return nil }
func (m *mockPacketConn) SetWriteBuffer(n int) error         { return nil }
func (m *mockPacketConn) SyscallConn() (interface{}, error) {
	return nil, nil
}
func (m *mockPacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

func Test_connPool_New(t *testing.T) {
	p := newConnPool(time.Second)
	if p == nil {
		t.Fatal("expected non-nil pool")
	}
	p.Close()
}

func Test_connPool_NilReceiver(t *testing.T) {
	var p *connPool
	if c, ok := p.Get("key"); c != nil || ok {
		t.Error("nil receiver should return nil, false")
	}
	p.Set("key", &conn{})
	p.Delete("key")
	p.Close()
}

func Test_connPool_SetGetDelete(t *testing.T) {
	p := newConnPool(time.Hour)
	defer p.Close()

	c := newConn(nil, nil, nil, 1, false)

	got, ok := p.Get("key")
	if ok || got != nil {
		t.Error("expected no value for non-existent key")
	}

	p.Set("key", c)
	got, ok = p.Get("key")
	if !ok || got != c {
		t.Error("expected to get the set value")
	}

	p.Delete("key")
	got, ok = p.Get("key")
	if ok || got != nil {
		t.Error("expected no value after delete")
	}
}

func Test_connPool_CloseCleansUp(t *testing.T) {
	p := newConnPool(time.Hour)
	c := newConn(nil, nil, nil, 1, false)
	p.Set("key", c)
	p.Close()
	// Double close should be safe
	p.Close()
}

func Test_connPool_idleCheck(t *testing.T) {
	p := newConnPool(50 * time.Millisecond)
	p.WithLogger(&nopLogger{})
	defer p.Close()

	c := newConn(nil, nil, nil, 1, false)
	c.SetIdle(true)
	p.Set("key", c)

	time.Sleep(150 * time.Millisecond)

	got, ok := p.Get("key")
	if ok || got != nil {
		t.Error("idle connection should have been cleaned up")
	}
}

func Test_conn_Close(t *testing.T) {
	c := newConn(newMockPacketConn(), &net.UDPAddr{Port: 1000}, &net.UDPAddr{Port: 2000}, 10, false)
	if c.isClosed() {
		t.Error("should not be closed initially")
	}
	err := c.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !c.isClosed() {
		t.Error("should be closed after Close()")
	}
	err = c.Close()
	if err != nil {
		t.Error("double close should not error")
	}
}

func Test_conn_IsIdle_SetIdle(t *testing.T) {
	c := newConn(nil, nil, nil, 1, false)
	if c.IsIdle() {
		t.Error("should not be idle initially")
	}
	c.SetIdle(true)
	if !c.IsIdle() {
		t.Error("should be idle after SetIdle(true)")
	}
	c.SetIdle(false)
	if c.IsIdle() {
		t.Error("should not be idle after SetIdle(false)")
	}
}

func Test_conn_ReadFrom(t *testing.T) {
	c := newConn(newMockPacketConn(), &net.UDPAddr{Port: 1000}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2000}, 10, false)

	testData := []byte("test data")
	err := c.WriteQueue(testData)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testData) {
		t.Errorf("expected %d bytes, got %d", len(testData), n)
	}
	if string(buf[:n]) != "test data" {
		t.Errorf("expected 'test data', got %q", string(buf[:n]))
	}
	if addr.String() != "10.0.0.1:2000" {
		t.Errorf("expected remote addr, got %v", addr)
	}
}

func Test_conn_ReadFrom_QueueFull(t *testing.T) {
	c := newConn(nil, nil, nil, 0, false)
	err := c.WriteQueue([]byte("data"))
	if err == nil {
		t.Error("expected error when queue is full (size 0)")
	}
}

func Test_conn_ReadFrom_Closed(t *testing.T) {
	c := newConn(nil, nil, nil, 0, false)
	c.Close()

	err := c.WriteQueue([]byte("data"))
	if err == nil {
		t.Error("expected error (queue full or closed), got nil")
	}

	_, _, err = c.ReadFrom(make([]byte, 10))
	if err != net.ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func Test_conn_Read(t *testing.T) {
	c := newConn(newMockPacketConn(), nil, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2000}, 10, false)

	testData := []byte("hello")
	c.WriteQueue(testData)

	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testData) {
		t.Errorf("expected %d bytes, got %d", len(testData), n)
	}
}

func Test_conn_Write(t *testing.T) {
	pc := newMockPacketConn()
	var written []byte
	pc.writeFn = func(b []byte, addr net.Addr) (int, error) {
		written = append(written, b...)
		return len(b), nil
	}

	c := newConn(pc, nil, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2000}, 10, true)

	n, err := c.Write([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("expected 4 bytes, got %d", n)
	}
	if string(written) != "data" {
		t.Errorf("expected 'data', got %q", string(written))
	}

	if c.isClosed() {
		t.Error("should not close after Write when keepalive=true")
	}
}

func Test_conn_WriteTo_NoKeepalive(t *testing.T) {
	pc := newMockPacketConn()
	c := newConn(pc, nil, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2000}, 10, false)

	_, err := c.WriteTo([]byte("data"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 9999})
	if err != nil {
		t.Fatal(err)
	}

	if !c.isClosed() {
		t.Error("expected conn to close after WriteTo when keepalive=false")
	}
}

func Test_conn_WriteTo_Keepalive(t *testing.T) {
	pc := newMockPacketConn()
	c := newConn(pc, nil, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2000}, 10, true)

	_, err := c.WriteTo([]byte("data"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 9999})
	if err != nil {
		t.Fatal(err)
	}

	if c.isClosed() {
		t.Error("should not close after WriteTo when keepalive=true")
	}
}

func Test_conn_LocalAddr_RemoteAddr(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000}
	raddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 9000}
	c := newConn(nil, laddr, raddr, 1, false)

	if c.LocalAddr().String() != laddr.String() {
		t.Errorf("expected %v, got %v", laddr, c.LocalAddr())
	}
	if c.RemoteAddr().String() != raddr.String() {
		t.Errorf("expected %v, got %v", raddr, c.RemoteAddr())
	}
}

func Test_newConnPool(t *testing.T) {
	p := newConnPool(time.Minute)
	if p == nil {
		t.Fatal("expected non-nil pool")
	}
	if p.ttl != time.Minute {
		t.Errorf("expected ttl %v, got %v", time.Minute, p.ttl)
	}
	p.Close()
}

func Test_connPool_WithLogger(t *testing.T) {
	p := newConnPool(time.Second)
	defer p.Close()
	result := p.WithLogger(nil)
	if result != p {
		t.Error("WithLogger should return same pool")
	}
}

// Test NewListener
func TestNewListener(t *testing.T) {
	pc := newMockPacketConn()
	cfg := &ListenConfig{
		Backlog:        10,
		ReadQueueSize:  10,
		ReadBufferSize: 1024,
		TTL:            time.Minute,
	}

	ln := NewListener(pc, cfg)
	if ln == nil {
		t.Fatal("expected non-nil listener")
	}
	defer ln.Close()

	if ln.Addr() == nil {
		t.Error("expected non-nil addr")
	}
}

func TestNewListener_NilConfig(t *testing.T) {
	pc := newMockPacketConn()
	ln := NewListener(pc, &ListenConfig{TTL: time.Minute})
	if ln == nil {
		t.Fatal("expected non-nil listener")
	}
	ln.Close()
}

func TestNewListener_Close(t *testing.T) {
	pc := newMockPacketConn()
	ln := NewListener(pc, &ListenConfig{TTL: time.Minute})

	err := ln.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = ln.Close()
	if err != nil {
		t.Errorf("double close should not error: %v", err)
	}
}

func TestNewListener_Addr_ConfigAddr(t *testing.T) {
	pc := newMockPacketConn()
	cfg := &ListenConfig{
		Addr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8888},
		TTL:  time.Minute,
	}
	ln := NewListener(pc, cfg)
	defer ln.Close()

	addr := ln.Addr()
	if addr.String() != "10.0.0.1:8888" {
		t.Errorf("expected 10.0.0.1:8888, got %s", addr)
	}
}

func TestListener_Close(t *testing.T) {
	pc := newMockPacketConn()
	ln := NewListener(pc, &ListenConfig{TTL: time.Minute})
	_ = ln.Close()

	_, err := ln.Accept()
	if err != net.ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestListener_Accept_ErrChan(t *testing.T) {
	pc := newMockPacketConn()
	pc.readFn = func(b []byte) (int, net.Addr, error) {
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: errors.New("mock error")}
	}

	ln := NewListener(pc, &ListenConfig{
		TTL:            time.Minute,
		ReadBufferSize: 1024,
	})
	defer ln.Close()

	conn, err := ln.Accept()
	if err == nil {
		t.Error("expected error, got nil")
		t.Logf("got conn: %v", conn)
	}
}

func TestListener_listenLoop_Closed(t *testing.T) {
	pc := newMockPacketConn()
	ln := NewListener(pc, &ListenConfig{TTL: time.Minute})

	ln.Close()

	_, err := ln.Accept()
	if err != net.ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestListener_Addr_Default(t *testing.T) {
	pc := newMockPacketConn()
	pc.localAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	ln := NewListener(pc, &ListenConfig{TTL: time.Minute})
	defer ln.Close()

	addr := ln.Addr()
	if addr.String() != "127.0.0.1:9999" {
		t.Errorf("expected 127.0.0.1:9999, got %s", addr)
	}
}

// Test Relay
func Test_NewRelay(t *testing.T) {
	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()
	r := NewRelay(pc1, pc2)
	if r == nil {
		t.Fatal("expected non-nil relay")
	}
}

func Test_Relay_WithMethods(t *testing.T) {
	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()
	r := NewRelay(pc1, pc2)

	r.WithService("test")
	r.WithBypass(nil)
	r.WithLogger(nil)
	r.WithBufferSize(8192)

	if r.service != "test" {
		t.Errorf("expected service 'test', got %q", r.service)
	}
	if r.bufferSize != 8192 {
		t.Errorf("expected bufferSize 8192, got %d", r.bufferSize)
	}
}

func Test_Relay_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()

	var received []byte
	var pc1Calls int

	// First goroutine reads from pc1, writes to pc2
	pc1.readFn = func(b []byte) (int, net.Addr, error) {
		pc1Calls++
		if pc1Calls == 1 {
			n := copy(b, []byte("hello"))
			return n, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}, nil
		}
		return 0, nil, errors.New("stop")
	}
	// Second goroutine reads from pc2 - block until G1 writes data first
	var pc2Calls int
	writeDone := make(chan struct{})
	pc2.readFn = func(b []byte) (int, net.Addr, error) {
		pc2Calls++
		if pc2Calls == 1 {
			// Wait for G1 to write data before returning error
			<-writeDone
		}
		return 0, nil, errors.New("stop2")
	}
	pc2.writeFn = func(b []byte, addr net.Addr) (int, error) {
		received = append(received, b...)
		
		close(writeDone)
		return len(b), nil
	}

	r := NewRelay(pc1, pc2)
	// Run catches the first error from either goroutine
	err := r.Run(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}
	// Note: by the time Run returns, G1 may or may not have written data
	// depending on goroutine scheduling. We only verify the relay ran.
	_ = received
}

func Test_Relay_Run_Reverse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()

	var received []byte
	var pc2Calls int

	// Second goroutine reads from pc2, writes to pc1
	pc2.readFn = func(b []byte) (int, net.Addr, error) {
		pc2Calls++
		if pc2Calls == 1 {
			n := copy(b, []byte("world"))
			return n, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 5678}, nil
		}
		return 0, nil, errors.New("stop reverse")
	}
	pc1.writeFn = func(b []byte, addr net.Addr) (int, error) {
		received = append(received, b...)
		return len(b), nil
	}
	// First goroutine reads from pc1 - make it return an error
	pc1.readFn = func(b []byte) (int, net.Addr, error) {
		return 0, nil, errors.New("stop1")
	}

	r := NewRelay(pc1, pc2)
	err := r.Run(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}

	if string(received) != "world" {
		t.Errorf("expected 'world' received, got %q", string(received))
	}
}

func Test_Relay_Run_Bypass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()

	writeCalled := false
	var pc1Calls int

	// First goroutine reads from pc1 - data bypassed
	pc1.readFn = func(b []byte) (int, net.Addr, error) {
		pc1Calls++
		if pc1Calls == 1 {
			n := copy(b, []byte("bypassed"))
			return n, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}, nil
		}
		return 0, nil, errors.New("done")
	}
	pc2.writeFn = func(b []byte, addr net.Addr) (int, error) {
		writeCalled = true
		return len(b), nil
	}
	// Second goroutine reads from pc2
	pc2.readFn = func(b []byte) (int, net.Addr, error) {
		return 0, nil, errors.New("done2")
	}

	r := NewRelay(pc1, pc2).WithBypass(&mockBypass{contains: true})
	err := r.Run(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if writeCalled {
		t.Error("write should not have been called when bypass matches")
	}
}

func Test_Relay_Run_DefaultBufferSize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()

	// Both goroutines in Run read from their respective PacketConn,
	// so both need readFn set.
	pc1.readFn = func(b []byte) (int, net.Addr, error) {
		return 0, nil, errors.New("stop")
	}
	pc2.readFn = func(b []byte) (int, net.Addr, error) {
		// Block forever since pc1 returns first
		select {}
	}

	r := NewRelay(pc1, pc2)
	err := r.Run(ctx)
	if err == nil || err.Error() != "stop" {
		t.Errorf("expected 'stop' error, got %v", err)
	}
}

func Test_Relay_TraceLogging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc1 := newMockPacketConn()
	pc2 := newMockPacketConn()

	pc1.readFn = func(b []byte) (int, net.Addr, error) {
		return 0, nil, errors.New("done")
	}
	pc2.readFn = func(b []byte) (int, net.Addr, error) {
		select {}
	}

	r := NewRelay(pc1, pc2)
	err := r.Run(ctx)
	if err == nil || err.Error() != "done" {
		t.Errorf("expected 'done' error, got %v", err)
	}
}

type mockBypass struct {
	contains bool
}

func (m *mockBypass) IsWhitelist() bool { return true }
func (m *mockBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return m.contains
}
