package proxyproto

import (
	"net"

	xio "github.com/go-gost/x/internal/io"
	proxyproto "github.com/pires/go-proxyproto"
)

type serverConn struct {
	net.Conn
}

func (c *serverConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	if conn, ok := c.Conn.(*proxyproto.Conn); ok {
		if tcpConn, ok := conn.TCPConn(); ok {
			return tcpConn.CloseRead()
		}
	}
	return xio.ErrUnsupported
}

func (c *serverConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	if conn, ok := c.Conn.(*proxyproto.Conn); ok {
		if tcpConn, ok := conn.TCPConn(); ok {
			return tcpConn.CloseWrite()
		}
	}
	return xio.ErrUnsupported
}

func WrapClientConn(ppv int, src, dst net.Addr, c net.Conn) net.Conn {
	if ppv <= 0 {
		return c
	}

	header := proxyproto.HeaderProxyFromAddrs(byte(ppv), src, dst)
	header.WriteTo(c)
	return c
}
