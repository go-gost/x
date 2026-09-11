package udp

import (
	"net"
)

// conn presents a dialed connection as a connected datagram socket: one
// Write/Read per datagram, the peer address always the connected one, and the
// address argument of WriteTo ignored. It covers both a raw *net.UDPConn and a
// wrapped base dialer (e.g. a p2p tunnel endpoint), neither of which the caller
// needs to tell apart.
type conn struct {
	net.Conn
}

func (c *conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}

func (c *conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(b)
	addr = c.RemoteAddr()
	return
}
