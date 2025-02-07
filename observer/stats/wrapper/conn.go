package wrapper

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
)

var (
	errUnsupport = errors.New("unsupported operation")
)

type conn struct {
	net.Conn
	stats  stats.Stats
	closed chan struct{}
	mu     sync.Mutex
}

func WrapConn(c net.Conn, pStats stats.Stats) net.Conn {
	if c == nil || pStats == nil {
		return c
	}

	pStats.Add(stats.KindTotalConns, 1)
	pStats.Add(stats.KindCurrentConns, 1)

	return &conn{
		Conn:   c,
		stats:  pStats,
		closed: make(chan struct{}),
	}
}

func (c *conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.stats.Add(stats.KindInputBytes, int64(n))
	return
}

func (c *conn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	c.stats.Add(stats.KindOutputBytes, int64(n))
	return
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}

	c.stats.Add(stats.KindCurrentConns, -1)
	return c.Conn.Close()
}

func (c *conn) SyscallConn() (rc syscall.RawConn, err error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		rc, err = sc.SyscallConn()
		return
	}
	err = errUnsupport
	return
}

func (c *conn) Metadata() metadata.Metadata {
	if md, ok := c.Conn.(metadata.Metadatable); ok {
		return md.Metadata()
	}
	return nil
}

type packetConn struct {
	net.PacketConn
	stats stats.Stats
}

func WrapPacketConn(pc net.PacketConn, stats stats.Stats) net.PacketConn {
	if stats == nil {
		return pc
	}
	return &packetConn{
		PacketConn: pc,
		stats:      stats,
	}
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	c.stats.Add(stats.KindInputBytes, int64(n))
	return
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	c.stats.Add(stats.KindOutputBytes, int64(n))
	return
}

func (c *packetConn) Metadata() metadata.Metadata {
	if md, ok := c.PacketConn.(metadata.Metadatable); ok {
		return md.Metadata()
	}
	return nil
}

type udpConn struct {
	net.PacketConn
	stats stats.Stats
}

func WrapUDPConn(pc net.PacketConn, stats stats.Stats) udp.Conn {
	return &udpConn{
		PacketConn: pc,
		stats:      stats,
	}
}

func (c *udpConn) RemoteAddr() net.Addr {
	if nc, ok := c.PacketConn.(xnet.RemoteAddr); ok {
		return nc.RemoteAddr()
	}
	return nil
}

func (c *udpConn) SetReadBuffer(n int) error {
	if nc, ok := c.PacketConn.(xnet.SetBuffer); ok {
		return nc.SetReadBuffer(n)
	}
	return errUnsupport
}

func (c *udpConn) SetWriteBuffer(n int) error {
	if nc, ok := c.PacketConn.(xnet.SetBuffer); ok {
		return nc.SetWriteBuffer(n)
	}
	return errUnsupport
}

func (c *udpConn) Read(b []byte) (n int, err error) {
	if nc, ok := c.PacketConn.(io.Reader); ok {
		n, err = nc.Read(b)
		if c.stats != nil {
			c.stats.Add(stats.KindInputBytes, int64(n))
		}
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if c.stats != nil {
		c.stats.Add(stats.KindInputBytes, int64(n))
	}
	return
}

func (c *udpConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		n, addr, err = nc.ReadFromUDP(b)
		if c.stats != nil {
			c.stats.Add(stats.KindInputBytes, int64(n))
		}
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		n, oobn, flags, addr, err = nc.ReadMsgUDP(b, oob)
		if c.stats != nil {
			c.stats.Add(stats.KindInputBytes, int64(n))
		}
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	if nc, ok := c.PacketConn.(io.Writer); ok {
		n, err = nc.Write(b)
		if c.stats != nil {
			c.stats.Add(stats.KindOutputBytes, int64(n))
		}
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	if c.stats != nil {
		c.stats.Add(stats.KindOutputBytes, int64(n))
	}
	return
}

func (c *udpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, err = nc.WriteToUDP(b, addr)
		if c.stats != nil {
			c.stats.Add(stats.KindOutputBytes, int64(n))
		}
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, oobn, err = nc.WriteMsgUDP(b, oob, addr)
		if c.stats != nil {
			c.stats.Add(stats.KindOutputBytes, int64(n))
		}
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) SyscallConn() (rc syscall.RawConn, err error) {
	if nc, ok := c.PacketConn.(syscall.Conn); ok {
		return nc.SyscallConn()
	}
	err = errUnsupport
	return
}

func (c *udpConn) SetDSCP(n int) error {
	if nc, ok := c.PacketConn.(xnet.SetDSCP); ok {
		return nc.SetDSCP(n)
	}
	return nil
}

func (c *udpConn) Metadata() metadata.Metadata {
	if md, ok := c.PacketConn.(metadata.Metadatable); ok {
		return md.Metadata()
	}
	return nil
}
