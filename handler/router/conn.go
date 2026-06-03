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

	buf := bufpool.Get(dlen)
	defer bufpool.Put(buf)

	n, err = io.ReadFull(c.Conn, buf)
	copy(b, buf[:n])

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

type lockWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func LockWriter(w io.Writer) io.Writer {
	return &lockWriter{w: w}
}

func (w *lockWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.w.Write(p)
}

func (w *lockWriter) Close() error {
	if closer, ok := w.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
