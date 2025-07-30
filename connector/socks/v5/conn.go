package v5

import (
	"bytes"
	"net"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/gosocks5"
)

type bindConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *bindConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *bindConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

type udpRelayConn struct {
	udpConn    *net.UDPConn
	tcpConn    net.Conn
	taddr      net.Addr
	bufferSize int
	logger     logger.Logger
}

func (c *udpRelayConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := bufpool.Get(c.bufferSize)
	defer bufpool.Put(buf)

	nn, err := c.udpConn.Read(buf)
	if err != nil {
		return
	}

	socksAddr := gosocks5.Addr{}
	header := gosocks5.UDPHeader{
		Addr: &socksAddr,
	}
	dgram := gosocks5.UDPDatagram{
		Header: &header,
	}
	_, err = dgram.ReadFrom(bytes.NewReader(buf[:nn]))
	if err != nil {
		return
	}

	n = copy(b, dgram.Data)
	addr, err = net.ResolveUDPAddr("udp", header.Addr.String())

	return
}

func (c *udpRelayConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *udpRelayConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	socksAddr := gosocks5.Addr{}
	if err = socksAddr.ParseFrom(addr.String()); err != nil {
		return
	}
	if socksAddr.Host == "" {
		socksAddr.Type = gosocks5.AddrIPv4
		socksAddr.Host = "127.0.0.1"
	}

	header := gosocks5.UDPHeader{
		Addr: &socksAddr,
	}
	dgram := gosocks5.UDPDatagram{
		Header: &header,
		Data:   b,
	}

	buf := bufpool.Get(c.bufferSize)
	defer bufpool.Put(buf)

	nn, err := dgram.WriteTo(bytes.NewBuffer(buf[:0]))
	if err != nil {
		return
	}
	if nn > int64(len(buf)) {
		nn = int64(len(buf))
	}

	_, err = c.udpConn.Write(buf[:nn])
	n = len(b)

	return
}

func (c *udpRelayConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *udpRelayConn) RemoteAddr() net.Addr {
	return c.taddr
}

func (c *udpRelayConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

func (c *udpRelayConn) Close() error {
	c.udpConn.Close()
	return c.tcpConn.Close()
}

func (c *udpRelayConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c *udpRelayConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *udpRelayConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}
