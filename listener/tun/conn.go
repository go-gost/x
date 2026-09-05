package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type conn struct {
	ifce   io.ReadWriteCloser
	laddr  net.Addr
	raddr  net.Addr
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
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
	return &net.OpError{Op: "set", Net: "tun", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tun", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tun", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Close() error {
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		c.ifce.Close()
	})
	return nil
}

func (c *conn) Context() context.Context {
	return c.ctx
}
