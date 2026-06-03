package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
)

// tcpConn wraps a TCP connection with response header buffering (wbuf).
//
// In non-noDelay mode, the relay.Response header is first written into wbuf.
// On the first Write() call, the buffered header and the data are sent together.
// This avoids sending a small relay frame before the data stream begins.
//
// Write() semantics:
//   - n always returns len(b) rather than the actual bytes written. This differs
//     from net.Conn's contract. The rationale: when wbuf has content, the actual
//     write is "wbuf + b" but the caller only cares that "b" was "processed".
type tcpConn struct {
	net.Conn
	wbuf bytes.Buffer
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	n = len(b) // always return len(b), not actual bytes written
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append data after the cached header
		_, err = c.wbuf.WriteTo(c.Conn)
		return
	}
	_, err = c.Conn.Write(b)
	return
}

// udpConn wraps UDP datagrams over a stream connection.
//
// When the GOST relay protocol carries UDP over a TCP/stream transport,
// a 2-byte big-endian length prefix frames each datagram. TCP is a stream
// protocol without message boundaries, so this framing is necessary.
//
// Datagram wire format:
//
//	[2-byte length (big-endian)][datagram payload]
//
// Read() flow:
//  1. Read 2-byte length prefix.
//  2. Read the datagram payload of the specified length.
//  3. If the caller's buffer is too small, allocate an internal buffer,
//     read the full datagram, then truncate on copy.
//
// Write() flow:
//  1. Reject data exceeding MaxUint16 (65535).
//  2. If wbuf has a cached header, append the length prefix + data to the
//     header and flush everything at once.
//  3. Otherwise write the length prefix then the data.
type udpConn struct {
	net.Conn
	wbuf bytes.Buffer
}

func (c *udpConn) Read(b []byte) (n int, err error) {
	var bb [2]byte
	_, err = io.ReadFull(c.Conn, bb[:])
	if err != nil {
		return
	}

	dlen := int(binary.BigEndian.Uint16(bb[:]))
	if len(b) >= dlen {
		return io.ReadFull(c.Conn, b[:dlen])
	}
	// Caller's buffer is too small; allocate internal buffer.
	buf := make([]byte, dlen)
	_, err = io.ReadFull(c.Conn, buf)
	n = copy(b, buf)

	return
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	if len(b) > math.MaxUint16 {
		err = errors.New("write: data maximum exceeded")
		return
	}

	n = len(b)
	if c.wbuf.Len() > 0 {
		// Wbuf has cached header; append length prefix + data and flush together.
		var bb [2]byte
		binary.BigEndian.PutUint16(bb[:], uint16(len(b)))
		c.wbuf.Write(bb[:])
		c.wbuf.Write(b)
		_, err = c.wbuf.WriteTo(c.Conn)
		return
	}

	// Write length prefix + data directly.
	var bb [2]byte
	binary.BigEndian.PutUint16(bb[:], uint16(len(b)))
	_, err = c.Conn.Write(bb[:])
	if err != nil {
		return
	}
	return c.Conn.Write(b)
}