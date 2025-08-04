package tap

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type conn struct {
	ifce   io.ReadWriteCloser
	laddr  net.Addr
	raddr  net.Addr
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *conn) Read(b []byte) (n int, err error) {
	return c.ifce.Read(b)
}

func (c *conn) Write(b []byte) (n int, err error) {
	return c.ifce.Write(b)
}

func (c *conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Close() (err error) {
	if c.cancel != nil {
		c.cancel()
	}
	return c.ifce.Close()
}

func (c *conn) Context() context.Context {
	return c.ctx
}
