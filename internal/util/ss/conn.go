package ss

import (
	"bytes"
	"net"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/gosocks5"
)

const (
	defaultBufferSize = 4096
)

var (
	_ net.PacketConn = (*UDPConn)(nil)
	_ net.Conn       = (*UDPConn)(nil)
)

type UDPConn struct {
	net.PacketConn
	raddr      net.Addr
	taddr      net.Addr
	bufferSize int
}

func UDPClientConn(c net.PacketConn, remoteAddr, targetAddr net.Addr, bufferSize int) *UDPConn {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	return &UDPConn{
		PacketConn: c,
		raddr:      remoteAddr,
		taddr:      targetAddr,
		bufferSize: bufferSize,
	}
}

func UDPServerConn(c net.PacketConn, remoteAddr net.Addr, bufferSize int) *UDPConn {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	return &UDPConn{
		PacketConn: c,
		raddr:      remoteAddr,
		bufferSize: bufferSize,
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := bufpool.Get(c.bufferSize)
	defer bufpool.Put(buf)

	n, _, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	saddr := gosocks5.Addr{}
	addrLen, err := saddr.ReadFrom(bytes.NewReader(buf[:n]))
	if err != nil {
		return
	}

	n = copy(b, buf[addrLen:n])
	addr, err = net.ResolveUDPAddr("udp", saddr.String())

	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	socksAddr := gosocks5.Addr{}
	if err = socksAddr.ParseFrom(addr.String()); err != nil {
		return
	}

	buf := bufpool.Get(c.bufferSize)
	defer bufpool.Put(buf)

	addrLen, err := socksAddr.Encode(buf)
	if err != nil {
		return
	}

	n = copy(buf[addrLen:], b)
	_, err = c.PacketConn.WriteTo(buf[:addrLen+n], c.raddr)

	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.raddr
}
