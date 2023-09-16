package com

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

type comAddr struct {
	port string
}

func (a *comAddr) Network() string {
	return "com"
}

func (a *comAddr) String() string {
	return a.port
}
