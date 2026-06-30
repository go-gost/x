package socks

import (
	"bytes"
	"net"
	"strconv"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/gosocks5"
)

type udpTunConn struct {
	net.Conn
	taddr net.Addr
}

func UDPTunClientConn(c net.Conn, targetAddr net.Addr) net.Conn {
	return &udpTunConn{
		Conn:  c,
		taddr: targetAddr,
	}
}

func UDPTunClientPacketConn(c net.Conn) net.PacketConn {
	return &udpTunConn{
		Conn: c,
	}
}

func UDPTunServerConn(c net.Conn) net.PacketConn {
	return &udpTunConn{
		Conn: c,
	}
}

func (c *udpTunConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	socksAddr := gosocks5.Addr{}
	header := gosocks5.UDPHeader{
		Addr: &socksAddr,
	}
	dgram := gosocks5.UDPDatagram{
		Header: &header,
		Data:   b,
	}
	_, err = dgram.ReadFrom(c.Conn)
	if err != nil {
		return
	}

	n = len(dgram.Data)
	if n > len(b) {
		n = copy(b, dgram.Data)
	}
	if net.ParseIP(socksAddr.Host) != nil {
		addr, err = net.ResolveUDPAddr("udp", socksAddr.String())
	} else {
		addr = &domainAddr{network: "udp", host: socksAddr.Host, port: int(socksAddr.Port)}
	}

	return
}

func (c *udpTunConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *udpTunConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	socksAddr := gosocks5.Addr{}
	if err = socksAddr.ParseFrom(addr.String()); err != nil {
		return
	}

	header := gosocks5.UDPHeader{
		Addr: &socksAddr,
	}
	dgram := gosocks5.UDPDatagram{
		Header: &header,
		Data:   b,
	}
	dgram.Header.Rsv = uint16(len(dgram.Data))
	dgram.Header.Frag = 0xff // UDP tun relay flag, used by shadowsocks
	_, err = dgram.WriteTo(c.Conn)
	n = len(b)

	return
}

func (c *udpTunConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

const (
	defaultBufferSize = 4096
)

type udpConn struct {
	net.PacketConn
	raddr      net.Addr
	taddr      net.Addr
	bufferSize int
}

func UDPConn(c net.PacketConn, bufferSize int) net.PacketConn {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	return &udpConn{
		PacketConn: c,
		bufferSize: bufferSize,
	}
}

// domainAddr is a net.Addr that preserves a domain name without resolving it.
// Returned by udpConn.ReadFrom when a SOCKS5 UDP datagram carries
// ATYP=DOMAINNAME, so that downstream consumers (e.g. relay-chain WriteTo) can
// forward the domain verbatim instead of forcing a local DNS lookup that would
// leak the query through the system resolver and bypass any configured resolver.
type domainAddr struct {
	network string
	host    string
	port    int
}

func (a *domainAddr) Network() string { return a.network }
func (a *domainAddr) String() string  { return net.JoinHostPort(a.host, strconv.Itoa(a.port)) }

// ReadFrom reads an UDP datagram.
// NOTE: for server side,
// the returned addr is the target address the client want to relay to.
func (c *udpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := bufpool.Get(c.bufferSize)
	defer bufpool.Put(buf)

	n, c.raddr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	socksAddr := gosocks5.Addr{}
	header := gosocks5.UDPHeader{
		Addr: &socksAddr,
	}
	hlen, err := header.ReadFrom(bytes.NewReader(buf[:n]))
	if err != nil {
		return
	}
	n = copy(b, buf[hlen:n])

	if net.ParseIP(socksAddr.Host) != nil {
		addr, err = net.ResolveUDPAddr("udp", socksAddr.String())
	} else {
		addr = &domainAddr{network: "udp", host: socksAddr.Host, port: int(socksAddr.Port)}
	}
	return
}

func (c *udpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *udpConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	socksAddr := gosocks5.Addr{}
	if err = socksAddr.ParseFrom(addr.String()); err != nil {
		return
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

	bw := bytes.NewBuffer(buf[:0])
	_, err = dgram.WriteTo(bw)
	if err != nil {
		return
	}

	_, err = c.PacketConn.WriteTo(bw.Bytes(), c.raddr)
	n = len(b)

	return
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.raddr
}
