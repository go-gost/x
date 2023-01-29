package net

import (
	"bufio"
	"io"
	"net"

	"github.com/go-gost/core/common/bufpool"
)

func Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		errc <- CopyBuffer(rw1, rw2, 8192)
	}()

	go func() {
		errc <- CopyBuffer(rw2, rw1, 8192)
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}

	return nil
}

func CopyBuffer(dst io.Writer, src io.Reader, bufSize int) error {
	buf := bufpool.Get(8192)
	defer bufpool.Put(buf)

	_, err := io.CopyBuffer(dst, src, *buf)
	return err
}

type bufferReaderConn struct {
	net.Conn
	br *bufio.Reader
}

func NewBufferReaderConn(conn net.Conn, br *bufio.Reader) net.Conn {
	return &bufferReaderConn{
		Conn: conn,
		br:   br,
	}
}

func (c *bufferReaderConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}
