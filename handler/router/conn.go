package router

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"

	"github.com/go-gost/core/common/bufpool"
)

// packetConn wraps a stream-oriented net.Conn and provides datagram-
// oriented Read/Write by adding a 2-byte big-endian length prefix.
//
// This adapter allows IP packets (which have variable length) to be
// sent over a TCP connection. Each logical "packet" is framed as:
//
//	┌──────────┬──────────────────┐
//	│ 2 bytes  │ N bytes          │
//	│ (length) │ (packet data)    │
//	└──────────┴──────────────────┘
//
// The maximum packet size is math.MaxUint16 (65535 bytes).
//
// # Read behavior
//
// Read reads exactly one framed packet. If the caller's buffer is
// large enough, the data is read directly into it. If the buffer is
// too small, the full frame is read into a temporary buffer and
// truncated to fit — the return value n is clamped to len(b) so
// b[:n] is always valid.
//
// # Write behavior
//
// Write prepends a 2-byte length header before writing to the
// underlying connection. Writes exceeding math.MaxUint16 are
// rejected with an error.
type packetConn struct {
	net.Conn
}

func (c *packetConn) Read(b []byte) (n int, err error) {
	var bb [2]byte
	_, err = io.ReadFull(c.Conn, bb[:])
	if err != nil {
		return
	}

	dlen := int(binary.BigEndian.Uint16(bb[:]))
	if len(b) >= dlen {
		return io.ReadFull(c.Conn, b[:dlen])
	}

	// The caller's buffer is too small for the full packet. Read the
	// complete frame from the underlying connection into a temporary
	// buffer, then copy as much as fits.  n is clamped to len(b) so
	// that b[:n] is never out of bounds — the excess data is silently
	// truncated.
	buf := bufpool.Get(dlen)
	defer bufpool.Put(buf)

	_, err = io.ReadFull(c.Conn, buf)
	n = copy(b, buf)

	return
}

func (c *packetConn) Write(b []byte) (n int, err error) {
	if len(b) > math.MaxUint16 {
		err = errors.New("write: data maximum exceeded")
		return
	}

	buf := bufpool.Get(len(b) + 2)
	defer bufpool.Put(buf)

	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	n = copy(buf[2:], b)

	return c.Conn.Write(buf)
}

// lockWriter wraps an io.Writer with a mutex to serialize writes.
//
// This is used as the writer stored in a Connector. Two goroutines may
// concurrently write to the same connector:
//   - handlePacket: writes when an IP packet is routed to the connector
//   - handleEntrypoint: writes when a packet arrives from another node
//
// Without serialization, concurrent Write calls to the underlying
// packetConn would interleave the 2-byte length headers with data,
// corrupting the stream.
//
// Both Write and Close hold the mutex to prevent racing on the
// underlying writer.
type lockWriter struct {
	w  io.Writer
	mu sync.Mutex
}

// LockWriter creates a mutex-guarded wrapper around w.
func LockWriter(w io.Writer) io.Writer {
	return &lockWriter{w: w}
}

func (w *lockWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.w.Write(p)
}

func (w *lockWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if closer, ok := w.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
