package net

import (
	"bufio"
	"io"
	"net"

	"github.com/go-gost/core/common/bufpool"
)

func Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 2)
	go func() {
		errc <- copyBuffer(rw1, rw2)
	}()

	go func() {
		errc <- copyBuffer(rw2, rw1)
	}()

	err := <-errc
	err2 := <-errc
	if err != nil && err != io.EOF {
		return err
	}

	if err2 != nil && err2 != io.EOF {
		return err2
	}

	return nil
}

func copyBuffer(dst io.Writer, src io.Reader) error {
	buf := bufpool.Get(4 * 1024)
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
