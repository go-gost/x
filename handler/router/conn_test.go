package router

import (
	"bytes"
	"io"
	"math"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// packetConn tests
// ---------------------------------------------------------------------------

func TestPacketConn_ReadWrite(t *testing.T) {
	var buf bytes.Buffer
	pc := &packetConn{&fakeConn{writeBuf: buf}}

	// Write via packetConn's Write method
	n, err := pc.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// packetConn.Write writes 2 bytes length-prefix + data, so n is the
	// total bytes written to the underlying conn.
	if n != 7 {
		t.Errorf("n = %d, want 7 (2-byte header + 5-byte payload)", n)
	}
}

func TestPacketConn_Write_ExceedsMaxUint16(t *testing.T) {
	pc := &packetConn{&fakeConn{}}
	large := make([]byte, math.MaxUint16+1)
	_, err := pc.Write(large)
	if err == nil {
		t.Error("Write: expected error for data exceeding MaxUint16")
	}
}

// ---------------------------------------------------------------------------
// lockWriter tests
// ---------------------------------------------------------------------------

func TestLockWriter_Write(t *testing.T) {
	var buf bytes.Buffer
	lw := LockWriter(&buf)

	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf = %q, want hello", buf.String())
	}
}

func TestLockWriter_Concurrent(t *testing.T) {
	var buf bytes.Buffer
	lw := LockWriter(&buf)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lw.Write([]byte("x"))
		}()
	}
	wg.Wait()

	if buf.Len() != 10 {
		t.Errorf("buf.Len = %d, want 10", buf.Len())
	}
}

func TestLockWriter_Close_Closer(t *testing.T) {
	closed := false
	lw := LockWriter(&closeWriter{
		closeFn: func() error { closed = true; return nil },
	})

	if err := lw.(io.Closer).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Error("underlying writer was not closed")
	}
}

func TestLockWriter_Close_NonCloser(t *testing.T) {
	// bytes.Buffer does NOT implement io.Closer
	var buf bytes.Buffer
	lw := LockWriter(&buf)

	if err := lw.(io.Closer).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestLockWriter_Close_Multiple(t *testing.T) {
	callCount := 0
	lw := LockWriter(&closeWriter{
		closeFn: func() error { callCount++; return nil },
	})

	lw.(io.Closer).Close()
	lw.(io.Closer).Close()

	// Close should be called each time since lockWriter.Close delegates
	// to the underlying closer without tracking.
	if callCount != 2 {
		t.Errorf("close called %d times, want 2", callCount)
	}
}

func TestLockWriter_WriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	lw := LockWriter(&buf)
	lw.(io.Closer).Close()

	// Write should still work after close (lockWriter doesn't track closed state)
	n, err := lw.Write([]byte("data"))
	if err != nil {
		t.Fatalf("Write after close: %v", err)
	}
	if n != 4 {
		t.Errorf("n = %d, want 4", n)
	}
}

// ---------------------------------------------------------------------------
// LockWriter function tests
// ---------------------------------------------------------------------------

func TestLockWriter_NilWriter(t *testing.T) {
	lw := LockWriter(nil)
	if lw == nil {
		t.Fatal("LockWriter(nil) returned nil")
	}

	// Writing through a lockWriter with a nil underlying writer will panic.
	defer func() {
		if r := recover(); r == nil {
			t.Error("Write to nil writer should panic")
		}
	}()
	lw.Write([]byte("data"))
}

// ---------------------------------------------------------------------------
// packetConn Round-trip test using pipeConn
// ---------------------------------------------------------------------------

func TestPacketConn_RoundTrip(t *testing.T) {
	a, b := newPipePair()
	defer a.Close()
	defer b.Close()

	pcA := &packetConn{a}
	pcB := &packetConn{b}

	data := []byte("hello world")

	// Write and read concurrently to avoid pipe blocking
	errCh := make(chan error, 1)
	go func() {
		_, werr := pcA.Write(data)
		errCh <- werr
	}()

	readBuf := make([]byte, 1024)
	nr, err := pcB.Read(readBuf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if nr != len(data) {
		t.Errorf("nr = %d, want %d", nr, len(data))
	}
	if string(readBuf[:nr]) != string(data) {
		t.Errorf("Read = %q, want %q", string(readBuf[:nr]), string(data))
	}

	if werr := <-errCh; werr != nil {
		t.Fatalf("Write: %v", werr)
	}
}

func TestPacketConn_Read_Empty(t *testing.T) {
	a, b := newPipePair()
	defer a.Close()
	defer b.Close()

	pcA := &packetConn{a}
	pcB := &packetConn{b}

	errCh := make(chan error, 1)
	go func() {
		_, werr := pcA.Write([]byte{})
		errCh <- werr
	}()

	readBuf := make([]byte, 1024)
	nr, err := pcB.Read(readBuf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if nr != 0 {
		t.Errorf("nr = %d, want 0", nr)
	}

	if werr := <-errCh; werr != nil {
		t.Fatalf("Write empty: %v", werr)
	}
}

func TestPacketConn_Read_BufferSmaller(t *testing.T) {
	a, b := newPipePair()
	defer a.Close()
	defer b.Close()

	pcA := &packetConn{a}
	pcB := &packetConn{b}

	data := []byte("this is a long message for testing")
	errCh := make(chan error, 1)
	go func() {
		_, werr := pcA.Write(data)
		errCh <- werr
	}()

	readBuf := make([]byte, 5)
	nr, err := pcB.Read(readBuf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if nr < 5 {
		t.Errorf("nr = %d, want at least 5", nr)
	}
	if string(readBuf[:5]) != "this " {
		t.Errorf("Read = %q, want %q", string(readBuf[:5]), "this ")
	}

	<-errCh
}

func TestPacketConn_Read_EOF(t *testing.T) {
	a, b := newPipePair()
	a.Close() // Close write end so b gets EOF

	pcB := &packetConn{b}
	readBuf := make([]byte, 1024)
	_, err := pcB.Read(readBuf)
	if err != io.EOF {
		t.Errorf("Read = %v, want EOF", err)
	}
}

