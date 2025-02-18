package ss

import (
	"bytes"
	"math"
	"net"

	"github.com/go-gost/gosocks5"
)

const (
	MaxMessageSize = math.MaxUint16
)

var (
	_ net.PacketConn = (*UDPConn)(nil)
	_ net.Conn       = (*UDPConn)(nil)
)

type UDPConn struct {
	net.PacketConn
	raddr net.Addr
	taddr net.Addr
}

func UDPClientConn(c net.PacketConn, remoteAddr, targetAddr net.Addr) *UDPConn {
	return &UDPConn{
		PacketConn: c,
		raddr:      remoteAddr,
		taddr:      targetAddr,
	}
}

func UDPServerConn(c net.PacketConn, remoteAddr net.Addr) *UDPConn {
	return &UDPConn{
		PacketConn: c,
		raddr:      remoteAddr,
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	var rbuf [MaxMessageSize]byte

	n, _, err = c.PacketConn.ReadFrom(rbuf[:])
	if err != nil {
		return
	}

	saddr := gosocks5.Addr{}
	addrLen, err := saddr.ReadFrom(bytes.NewReader(rbuf[:n]))
	if err != nil {
		return
	}

	n = copy(b, rbuf[addrLen:n])
	addr, err = net.ResolveUDPAddr("udp", saddr.String())

	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var wbuf [MaxMessageSize]byte

	socksAddr := gosocks5.Addr{}
	if err = socksAddr.ParseFrom(addr.String()); err != nil {
		return
	}

	addrLen, err := socksAddr.Encode(wbuf[:])
	if err != nil {
		return
	}

	n = copy(wbuf[addrLen:], b)
	_, err = c.PacketConn.WriteTo(wbuf[:addrLen+n], c.raddr)

	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.raddr
}
