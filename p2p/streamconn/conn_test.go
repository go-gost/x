package streamconn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
)

// fakeStream is an in-memory Stream: recvCh feeds Recv, sendCh collects Send.
type fakeStream struct {
	ctx    context.Context
	recvCh chan *proto.Chunk
	sendCh chan *proto.Chunk
	sends  atomic.Int32
	recvs  atomic.Int32
}

func newFakeStream(ctx context.Context) *fakeStream {
	return &fakeStream{
		ctx:    ctx,
		recvCh: make(chan *proto.Chunk, 64),
		sendCh: make(chan *proto.Chunk, 64),
	}
}

func (f *fakeStream) Send(c *proto.Chunk) error {
	f.sends.Add(1)
	f.sendCh <- c
	return nil
}

func (f *fakeStream) Recv() (*proto.Chunk, error) {
	f.recvs.Add(1)
	select {
	case c := <-f.recvCh:
		return c, nil
	case <-f.ctx.Done():
		return nil, io.EOF
	}
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met in time: %s", what)
}

func TestFrameRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, 255, 256, 65535} {
		payload := bytes.Repeat([]byte{0xab}, n)
		var buf bytes.Buffer
		if err := WriteFrame(&buf, payload); err != nil {
			t.Fatalf("n=%d WriteFrame: %v", n, err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("n=%d ReadFrame: %v", n, err)
		}
		if n == 0 {
			if got != nil {
				t.Fatalf("n=0: want nil, got %v", got)
			}
			continue
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: payload mismatch", n)
		}
	}
}

// TestReadFrameFragmented feeds a frame header + payload split across writes
// (and TCP-style arrivals) to prove io.ReadFull reassembly.
func TestReadFrameFragmented(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		c1.Write([]byte{0x00, 0x03, 'a'})
		time.Sleep(10 * time.Millisecond)
		c1.Write([]byte("b"))
		time.Sleep(10 * time.Millisecond)
		c1.Write([]byte("c"))
		c1.Close()
	}()
	got, err := ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q want %q", got, "abc")
	}
}

func TestReadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(ctx)
	c := New(fs, func() {}, "tcp", nil, nil)
	defer c.Close()

	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	start := time.Now()
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("Read returned after %v, want the deadline to have applied", elapsed)
	}

	// Clearing the deadline lets the next Read consume data again.
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { fs.recvCh <- &proto.Chunk{Data: []byte("ping")} }()
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("Read after deadline clear = %q, %v; want ping", buf[:n], err)
	}
}

// TestBackpressure proves the one-chunk handoff throttles Recv: while the
// consumer is idle the pump must not fetch a third chunk.
func TestBackpressure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(ctx)
	for i := range 5 {
		fs.recvCh <- &proto.Chunk{Data: []byte{byte(i)}}
	}
	c := New(fs, func() {}, "tcp", nil, nil)
	defer c.Close()

	// Pump: fetch 1 -> deliver, fetch 2 -> blocked sending. No fetch 3.
	waitFor(t, "pump fetched two chunks", func() bool { return fs.recvs.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := fs.recvs.Load(); n != 2 {
		t.Fatalf("Recv calls = %d while consumer idle, want 2 (backpressure)", n)
	}

	// One Read frees the slot; the pump advances by exactly one fetch.
	buf := make([]byte, 8)
	if n, err := c.Read(buf); err != nil || n != 1 || buf[0] != 0 {
		t.Fatalf("Read = %d, %v, %v; want the first chunk", n, buf[:n], err)
	}
	waitFor(t, "pump advanced by one", func() bool { return fs.recvs.Load() == 3 })
	time.Sleep(50 * time.Millisecond)
	if n := fs.recvs.Load(); n != 3 {
		t.Fatalf("Recv calls = %d after one Read, want 3 (one slot freed, one fetch)", n)
	}
}

func TestFramedDatagrams(t *testing.T) {
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	a2b := make(chan *proto.Chunk, 64)
	b2a := make(chan *proto.Chunk, 64)
	connA := New(&fakeStream{ctx: ctxA, recvCh: b2a, sendCh: a2b}, cancelA, "udp", nil, nil)
	connB := New(&fakeStream{ctx: ctxB, recvCh: a2b, sendCh: b2a}, cancelB, "udp", nil, nil)
	defer connA.Close()
	defer connB.Close()

	// One datagram per Write/Read, boundaries preserved.
	connA.Write([]byte("hello"))
	buf := make([]byte, 64)
	if n, err := connB.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, %v; want hello", buf[:n], err)
	}
	connA.Write([]byte("a"))
	connA.Write([]byte("bb"))
	if n, err := connB.Read(buf); err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("Read = %q, %v; want single-byte datagram", buf[:n], err)
	}
	if n, err := connB.Read(buf); err != nil || n != 2 || string(buf[:n]) != "bb" {
		t.Fatalf("Read = %q, %v; want bb (no coalescing)", buf[:n], err)
	}

	// An empty datagram reads as 0 bytes, not EOF.
	connA.Write(nil)
	if n, err := connB.Read(buf); err != nil || n != 0 {
		t.Fatalf("Read = %d, %v; want empty datagram (0, nil)", n, err)
	}

	// Oversized relative to the read buffer: truncated, remainder dropped,
	// and the next Read gets the next datagram — not the leftover bytes.
	connA.Write(bytes.Repeat([]byte{7}, 10))
	if n, err := connB.Read(make([]byte, 4)); err != nil || n != 4 {
		t.Fatalf("Read = %d, %v; want truncation to 4", n, err)
	}
	connA.Write([]byte("z"))
	if n, err := connB.Read(buf); err != nil || string(buf[:n]) != "z" {
		t.Fatalf("Read = %q, %v; want z (remainder dropped)", buf[:n], err)
	}
}

// TestFramedAssemblesAcrossChunks feeds one frame split across many small
// chunks (the host pipes with io.Copy, so chunk boundaries are arbitrary) and
// asserts the datagram reassembles — and that the assembly buffer is bounded
// by the received bytes, never by the frame header's claimed length.
func TestFramedAssemblesAcrossChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(ctx)
	c := New(fs, func() {}, "udp", nil, nil)
	defer c.Close()

	payload := bytes.Repeat([]byte{0x5a}, 5000)
	var frame bytes.Buffer
	if err := WriteFrame(&frame, payload); err != nil {
		t.Fatal(err)
	}
	b := frame.Bytes()
	for len(b) > 0 {
		n := min(7, len(b))
		fs.recvCh <- &proto.Chunk{Data: append([]byte{}, b[:n]...)}
		b = b[n:]
	}
	buf := make([]byte, 8192)
	n, err := c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("Read = %d bytes, %v; want the reassembled datagram", n, err)
	}
	c.mu.Lock()
	rb := c.rb
	c.mu.Unlock()
	if rb != nil {
		t.Fatalf("rb = %d bytes after one frame, want nil (backing array dropped)", len(rb))
	}

	// A frame that never completes: rb holds exactly the bytes that arrived
	// (2 header + 1000), not the claimed 65535.
	fs2 := newFakeStream(ctx)
	c2 := New(fs2, func() {}, "udp", nil, nil)
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 65535)
	fs2.recvCh <- &proto.Chunk{Data: hdr[:]}
	fs2.recvCh <- &proto.Chunk{Data: bytes.Repeat([]byte{1}, 1000)}
	if _, err := c2.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want deadline (frame incomplete)", err)
	}
	c2.mu.Lock()
	rb2 := len(c2.rb)
	c2.mu.Unlock()
	if rb2 != 1002 {
		t.Fatalf("rb = %d bytes for a partial frame, want 1002 (received bytes only)", rb2)
	}
}

func TestWriteSplitsChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(ctx)
	c := New(fs, func() {}, "tcp", nil, nil)
	defer c.Close()

	payload := bytes.Repeat([]byte{0x5a}, writeChunkSize+16)
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v; want %d", n, err, len(payload))
	}
	c1 := <-fs.sendCh
	c2 := <-fs.sendCh
	if len(c1.Data) != writeChunkSize || len(c2.Data) != 16 {
		t.Fatalf("chunk sizes = %d, %d; want %d, 16", len(c1.Data), len(c2.Data), writeChunkSize)
	}
	if !bytes.Equal(append(c1.Data, c2.Data...), payload) {
		t.Fatal("split payload mismatch")
	}
	select {
	case extra := <-fs.sendCh:
		t.Fatalf("unexpected third Send: %d bytes", len(extra.Data))
	default:
	}
}

// TestPumpCancelUnblocksRead: when the transport dies while the pump is parked
// on the handoff (no Close, no Recv error yet — e.g. the client aborts a
// server stream), the reader must still get a terminal error. A pump that
// exited silently here would hang the host-side pipe forever.
func TestPumpCancelUnblocksRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(ctx)
	fs.recvCh <- &proto.Chunk{Data: []byte{1}}
	fs.recvCh <- &proto.Chunk{Data: []byte{2}}
	c := New(fs, func() {}, "tcp", nil, nil)
	defer c.Close()

	waitFor(t, "pump parked on the handoff", func() bool { return fs.recvs.Load() == 2 })
	cancel()

	buf := make([]byte, 4)
	if n, err := c.Read(buf); err != nil || n != 1 {
		t.Fatalf("Read = %d, %v; want the buffered chunk first", n, err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second)) // hang guard
	if _, err := c.Read(buf); err == nil {
		t.Fatal("Read after the pump died = nil error, want the terminal error")
	}
}

// TestTerminalEOFKeepsBufferedChunk: a chunk already delivered when the
// terminal state arrives (final chunk + clean EOF together) must still be
// readable — the select must prefer the chunk, not drop it for the error.
func TestTerminalEOFKeepsBufferedChunk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(ctx)
	fs.recvCh <- &proto.Chunk{Data: []byte("last")}
	c := New(fs, func() {}, "tcp", nil, nil)
	defer c.Close()

	waitFor(t, "chunk delivered then parked", func() bool { return fs.recvs.Load() == 2 })
	cancel() // Recv reports EOF: the chunk and the terminal state are both pending

	buf := make([]byte, 8)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "last" {
		t.Fatalf("Read = %q, %v; want the buffered last chunk", buf[:n], err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second)) // hang guard
	if _, err := c.Read(buf); err == nil {
		t.Fatal("Read after the last chunk = nil error, want io.EOF")
	}
}

// TestReadDeadlineUpdateWakes covers the net.Conn contract that a deadline set
// while a Read is blocked applies to that Read (the usual interrupt idiom).
func TestReadDeadlineUpdateWakes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := New(newFakeStream(ctx), func() {}, "tcp", nil, nil)
	defer c.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 4))
		errCh <- err
	}()
	time.Sleep(30 * time.Millisecond) // let the Read park
	c.SetReadDeadline(time.Now())
	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read err = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetReadDeadline did not wake the parked Read")
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := New(newFakeStream(ctx), func() {}, "tcp", nil, nil)

	go func() {
		time.Sleep(20 * time.Millisecond)
		c.Close()
	}()
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read err = %v, want net.ErrClosed", err)
	}
	// Idempotent close.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

func TestWriteDeadlineSupport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Server side (no abort): a parked Send cannot be interrupted, so write
	// deadlines are rejected.
	c := New(newFakeStream(ctx), nil, "tcp", nil, nil)
	defer c.Close()
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
		t.Fatal("SetWriteDeadline on a server stream = nil, want not-supported error")
	}
	if err := c.SetDeadline(time.Now().Add(time.Second)); err == nil {
		t.Fatal("SetDeadline on a server stream = nil, want the write side surfaced")
	}

	// Client side: accepted; an expired deadline fails the write fast.
	ca := New(newFakeStream(ctx), func() {}, "tcp", nil, nil)
	defer ca.Close()
	if err := ca.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write err = %v, want os.ErrDeadlineExceeded", err)
	}
}
