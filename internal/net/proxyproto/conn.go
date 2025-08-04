package proxyproto

import (
	"context"
	"net"
	"strconv"

	xio "github.com/go-gost/x/internal/io"
	proxyproto "github.com/pires/go-proxyproto"
)

type serverConn struct {
	net.Conn
	ctx context.Context
}

func (c *serverConn) Context() context.Context {
	return c.ctx
}

func (c *serverConn) RemoteAddr() net.Addr {
	if conn, ok := c.Conn.(*proxyproto.Conn); ok {
		return conn.Raw().RemoteAddr()
	}
	return c.Conn.RemoteAddr()
}

func (c *serverConn) LocalAddr() net.Addr {
	if conn, ok := c.Conn.(*proxyproto.Conn); ok {
		return conn.Raw().LocalAddr()
	}
	return c.Conn.LocalAddr()
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
	if ppv <= 0 || c == nil {
		return c
	}

	if src = convertAddr(src); src == nil {
		return c
	}
	if dst = convertAddr(dst); dst == nil {
		return c
	}

	header := proxyproto.HeaderProxyFromAddrs(byte(ppv), src, dst)
	header.WriteTo(c)
	return c
}

func convertAddr(addr net.Addr) net.Addr {
	if addr == nil {
		return nil
	}

	host, sp, _ := net.SplitHostPort(addr.String())
	ip := net.ParseIP(host)
	port, _ := strconv.Atoi(sp)

	if ip == nil || ip.Equal(net.IPv6zero) {
		ip = net.IPv4zero
	}

	switch addr.Network() {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{
			IP:   ip,
			Port: port,
		}

	default:
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	}
}
