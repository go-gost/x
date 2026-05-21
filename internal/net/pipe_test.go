package net

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn is a fully controllable in-memory connection for testing Pipe.
// It supports proper half-close semantics: CloseRead only stops reads,
// CloseWrite only stops writes, and Close stops both.
type pipeConn struct {
	readBuf     []byte
	readPos     int
	writeBuf    []byte
	readClosed  bool
	writeClosed bool
	closedCh    chan struct{}
	readDead    time.Time
	writeDead   time.Time
	readErr     error // error to return on next Read
	eofAfter    int   // return io.EOF after this many bytes total read (-1 = never)
	bytesRead   int
}

func newPipeConn(data []byte) *pipeConn {
	return &pipeConn{
		readBuf:  data,
		closedCh: make(chan struct{}),
	}
}

func (pc *pipeConn) Read(p []byte) (int, error) {
	select {
	case <-pc.closedCh:
		return 0, net.ErrClosed
	default:
	}
	if pc.readClosed {
		return 0, net.ErrClosed
	}
	if pc.readErr != nil {
		err := pc.readErr
		pc.readErr = nil
		return 0, err
	}
	if pc.readPos >= len(pc.readBuf) {
		// eofAfter=-1 means sleep briefly then return (0, nil) to simulate
		// a connection that's still open but has no data yet.
		// This avoids busy-looping while still preventing EOF.
		if pc.eofAfter < 0 {
			time.Sleep(10 * time.Millisecond)
			return 0, nil // no data, no error, no EOF
		}
		return 0, io.EOF
	}
	n := copy(p, pc.readBuf[pc.readPos:])
	pc.readPos += n
	pc.bytesRead += n
	return n, nil
}

func (pc *pipeConn) Write(p []byte) (int, error) {
	select {
	case <-pc.closedCh:
		return 0, net.ErrClosed
	default:
	}
	if pc.writeClosed {
		return 0, net.ErrClosed
	}
	pc.writeBuf = append(pc.writeBuf, p...)
	return len(p), nil
}

func (pc *pipeConn) Close() error {
	select {
	case <-pc.closedCh:
	default:
		close(pc.closedCh)
	}
	return nil
}

func (pc *pipeConn) CloseRead() error {
	pc.readClosed = true
	return nil
}

func (pc *pipeConn) CloseWrite() error {
	pc.writeClosed = true
	return nil
}

func (pc *pipeConn) SetReadDeadline(t time.Time) error {
	pc.readDead = t
	return nil
}

func (pc *pipeConn) SetWriteDeadline(t time.Time) error {
	pc.writeDead = t
	return nil
}

func TestPipe_NormalTransfer(t *testing.T) {
	ctx := context.Background()
	c1 := newPipeConn([]byte("hello from c1"))
	c2 := newPipeConn([]byte("hello from c2"))

	err := Pipe(ctx, c1, c2)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// c2's writeBuf has data from c1
	if string(c2.writeBuf) != "hello from c1" {
		t.Errorf("c2.writeBuf = %q, want %q", string(c2.writeBuf), "hello from c1")
	}
	// c1's writeBuf has data from c2
	if string(c1.writeBuf) != "hello from c2" {
		t.Errorf("c1.writeBuf = %q, want %q", string(c1.writeBuf), "hello from c2")
	}
}

func TestPipe_ImmediateEOF(t *testing.T) {
	ctx := context.Background()
	// Empty read buffers produce immediate EOF, simulating closed connections
	c1 := newPipeConn(nil)
	c2 := newPipeConn(nil)

	err := Pipe(ctx, c1, c2)
	if err != nil {
		t.Errorf("expected nil error (EOF is not an error from Pipe), got %v", err)
	}
}

func TestPipe_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// These never produce EOF and never error, so Pipe will run until canceled
	c1 := newPipeConn(nil)
	c2 := newPipeConn(nil)
	c1.eofAfter = -1 // disable EOF
	c2.eofAfter = -1

	// Start cancellation in a goroutine
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Pipe(ctx, c1, c2)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func TestPipe_ContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c1 := newPipeConn(nil)
	c1.eofAfter = -1
	c2 := newPipeConn(nil)
	c2.eofAfter = -1

	err := Pipe(ctx, c1, c2)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func TestPipe_ReadError(t *testing.T) {
	ctx := context.Background()
	readErr := errors.New("read failure")
	c1 := newPipeConn(nil)
	c1.readErr = readErr
	// c2 also has a read error so both goroutines terminate
	otherErr := errors.New("other error")
	c2 := newPipeConn(nil)
	c2.readErr = otherErr

	err := Pipe(ctx, c1, c2)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestPipe_WriteError(t *testing.T) {
	ctx := context.Background()
	c1 := newPipeConn([]byte("data"))
	// c2 has its write side pre-closed
	c2 := newPipeConn(nil)
	c2.writeClosed = true

	err := Pipe(ctx, c1, c2)
	if err == nil {
		t.Error("expected write error, got nil")
	}
}

func Test_readDeadliner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	r := &mockReadWriteCloser{data: []byte("testdata")}
	rd := &readDeadliner{Reader: r, ctx: ctx}

	// Normal read
	buf := make([]byte, 8)
	n, err := rd.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n != 8 || string(buf[:n]) != "testdata" {
		t.Errorf("expected 'testdata', got %q", string(buf[:n]))
	}

	// Context canceled
	cancel()
	_, err = rd.Read(buf)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func Test_halfClose(t *testing.T) {
	// pipeConn supports CloseRead and CloseWrite (success).
	// CloseWrite returns nil (successful half-close), which sets a read deadline on dst.
	src := newPipeConn(nil)
	dst := newPipeConn(nil)
	halfClose(src, dst)
	if !src.readClosed {
		t.Error("src should have CloseRead called")
	}
	if !dst.writeClosed {
		t.Error("dst should have CloseWrite called (success path)")
	}
	if dst.readDead.IsZero() {
		t.Error("dst should have read deadline set after successful CloseWrite")
	}
}

func Test_halfClose_MockReadWriteCloser(t *testing.T) {
	// mockReadWriteCloser has CloseRead, but CloseWrite returns ErrUnsupported -> dst.Close()
	src2 := &mockReadWriteCloser{}
	dst2 := &mockReadWriteCloser{}
	halfClose(src2, dst2)
	if !src2.readClosed {
		t.Error("src should have CloseRead called")
	}
	if !dst2.closed {
		t.Error("dst should be fully closed when CloseWrite is ErrUnsupported")
	}
}

func Test_forceClose(t *testing.T) {
	c1 := newPipeConn(nil)
	c2 := newPipeConn(nil)
	forceClose(c1, c2, nil)
	// Check that closedCh is closed
	select {
	case <-c1.closedCh:
	default:
		t.Error("c1 should be closed")
	}
	select {
	case <-c2.closedCh:
	default:
		t.Error("c2 should be closed")
	}
}

func Test_pipeHalf(t *testing.T) {
	ctx := context.Background()
	src := newPipeConn([]byte("hello world"))
	dst := newPipeConn(nil)

	err := pipeHalf(ctx, src, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(dst.writeBuf) != "hello world" {
		t.Errorf("dst.writeBuf = %q, want %q", string(dst.writeBuf), "hello world")
	}
}

func Test_pipeHalf_ReadError(t *testing.T) {
	ctx := context.Background()
	readErr := errors.New("read failed")
	src := newPipeConn(nil)
	src.readErr = readErr
	dst := newPipeConn(nil)

	err := pipeHalf(ctx, src, dst, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func Test_pipeHalf_WriteError(t *testing.T) {
	ctx := context.Background()
	src := newPipeConn([]byte("data"))
	dst := newPipeConn(nil)
	dst.writeClosed = true

	err := pipeHalf(ctx, src, dst, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func Test_pipeHalf_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := newPipeConn([]byte("data"))
	src.eofAfter = -1
	dst := newPipeConn(nil)

	err := pipeHalf(ctx, src, dst, 0)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func TestPipe_CtxDoneWithError(t *testing.T) {
	// Test the ctx.Done() path where firstErr is non-nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1 := newPipeConn(nil)
	c1.readErr = errors.New("error before cancel")
	c1.eofAfter = -1
	c2 := newPipeConn(nil)
	c2.eofAfter = -1

	done := make(chan error, 1)
	go func() {
		done <- Pipe(ctx, c1, c2)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	err := <-done
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestPipe_CtxDoneWithoutError(t *testing.T) {
	// Standard ctx.Done path with no prior error → returns ctx.Err()
	ctx, cancel := context.WithCancel(context.Background())

	c1 := newPipeConn(nil)
	c1.eofAfter = -1
	c2 := newPipeConn(nil)
	c2.eofAfter = -1

	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	err := Pipe(ctx, c1, c2)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func TestTransport_ReturnsError(t *testing.T) {
	// Both directions must return errors since Transport reads one from errc
	readErr := errors.New("not EOF error")
	rw1 := &mockReadWriter{readErr: readErr}
	rw2 := &mockReadWriter{readErr: errors.New("other error")}

	err := Transport(rw1, rw2)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func Test_halfClose_NoCloseWriteInterface(t *testing.T) {
	// Test the path where dst doesn't implement CloseWrite
	type noCloseWrite struct {
		*mockReadWriteCloser
	}

	src := &mockReadWriteCloser{}
	// Create a type that doesn't have CloseWrite (use a type without the method)
	// Actually, we need a type that implements io.ReadWriteCloser but NOT CloseWrite
	dst := &noCloseWriteCloser{}
	halfClose(src, dst)
	if !dst.closed {
		// halfClose checks cw, ok := dst.(xio.CloseWrite) → false
		// falls through to dst.Close()
		t.Error("dst should be closed when CloseWrite is not available")
	}
}

type noCloseWriteCloser struct {
	closed bool
}

func (c *noCloseWriteCloser) Read(p []byte) (int, error)  { return 0, nil }
func (c *noCloseWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (c *noCloseWriteCloser) Close() error                { c.closed = true; return nil }
