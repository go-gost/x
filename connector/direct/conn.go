package direct

import (
	"io"
	"net"
	"time"
)

type conn struct{}

func (c *conn) Close() error {
	return nil
}

func (c *conn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (c *conn) Write(b []byte) (n int, err error) {
	return 0, io.ErrClosedPipe
}

func (c *conn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return nil
}
