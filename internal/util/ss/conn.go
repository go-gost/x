package ss

import (
	"net"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

type udpConn struct {
	net.PacketConn
	targetAddr net.Addr
}

func UDPClientConn(c net.PacketConn, targetAddr net.Addr, client *core.UDPClient) net.Conn {
	return &udpConn{
		PacketConn: client.WrapConn(c),
		targetAddr: targetAddr,
	}
}

func (c *udpConn) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *udpConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.targetAddr)
}

func (c *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	target := socks.ParseAddr(addr.String())
	return c.PacketConn.WriteTo(b, core.NewUDPClientPacketAddr(target, c.LocalAddr()))
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.targetAddr
}
