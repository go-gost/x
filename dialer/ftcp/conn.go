package ftcp

import (
	"net"
	"time"
)

type fakeTCPConn struct {
	raddr net.Addr
	pc    net.PacketConn
}

func (c *fakeTCPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.pc.ReadFrom(b)
	return
}

func (c *fakeTCPConn) Write(b []byte) (n int, err error) {
	return c.pc.WriteTo(b, c.raddr)
}

func (c *fakeTCPConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *fakeTCPConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}

func (c *fakeTCPConn) SetDeadline(t time.Time) error {
	return c.pc.SetDeadline(t)
}

func (c *fakeTCPConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *fakeTCPConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}

func (c *fakeTCPConn) Close() error {
	return c.pc.Close()
}
