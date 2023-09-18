package serial

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type conn struct {
	port   io.ReadWriteCloser
	laddr  net.Addr
	raddr  net.Addr
	cancel context.CancelFunc
}

func NewConn(port io.ReadWriteCloser, addr net.Addr, cancel context.CancelFunc) net.Conn {
	return &conn{
		port:   port,
		laddr:  addr,
		raddr:  &Addr{Port: "@"},
		cancel: cancel,
	}
}

func (c *conn) Read(b []byte) (n int, err error) {
	return c.port.Read(b)
}

func (c *conn) Write(b []byte) (n int, err error) {
	return c.port.Write(b)
}

func (c *conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "com", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "com", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "com", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Close() (err error) {
	if c.cancel != nil {
		c.cancel()
	}
	return c.port.Close()
}

type Addr struct {
	Port string
}

func (a *Addr) Network() string {
	return "serial"
}

func (a *Addr) String() string {
	return a.Port
}
