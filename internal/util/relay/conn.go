package relay

import (
	"net"
	"strconv"
	"sync"

	"github.com/go-gost/gosocks5"
	"github.com/go-gost/relay"
)

func StatusText(code uint8) string {
	switch code {
	case relay.StatusBadRequest:
		return "Bad Request"
	case relay.StatusForbidden:
		return "Forbidden"
	case relay.StatusHostUnreachable:
		return "Host Unreachable"
	case relay.StatusInternalServerError:
		return "Internal Server Error"
	case relay.StatusNetworkUnreachable:
		return "Network Unreachable"
	case relay.StatusServiceUnavailable:
		return "Service Unavailable"
	case relay.StatusTimeout:
		return "Timeout"
	case relay.StatusUnauthorized:
		return "Unauthorized"
	default:
		return ""
	}
}

// udpTunConn frames UDP datagrams onto a stream connection as SOCKS5 UDP
// datagrams. One such conn is shared by every endpoint multiplexed over a
// reverse tunnel, so several handlers write to the same stream concurrently.
//
// A frame is not written atomically: UDPDatagram.WriteTo issues three separate
// Write calls (RSV/FRAG, address, payload). Each Write is concurrency-safe on
// its own, but without serialization the frames interleave between those calls,
// corrupting datagrams and leaving half a header in the stream — which the far
// end reads as io.ErrUnexpectedEOF and answers by tearing down and rebinding
// the whole tunnel. wmu makes one whole frame exclusive.
type udpTunConn struct {
	net.Conn
	taddr net.Addr
	wmu   sync.Mutex
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

// domainAddr is a net.Addr that preserves a domain name without resolving it.
// Returned by udpTunConn.ReadFrom when a relay UDP datagram carries
// ATYP=DOMAINNAME, so the relay handler can resolve it through the configured
// resolver instead of leaking the query through the system resolver.
type domainAddr struct {
	network string
	host    string
	port    int
}

func (a *domainAddr) Network() string { return a.network }
func (a *domainAddr) String() string  { return net.JoinHostPort(a.host, strconv.Itoa(a.port)) }

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

	// Hold the write lock for the whole frame, not just for the writes the
	// datagram happens to make.
	c.wmu.Lock()
	_, err = dgram.WriteTo(c.Conn)
	c.wmu.Unlock()
	n = len(b)

	return
}

func (c *udpTunConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}
