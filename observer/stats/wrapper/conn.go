package wrapper

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
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

// WrapConn wraps a net.Conn to track connection and traffic statistics.
// It increments total and current connection counts, and tracks bytes
// read and written. On Close, it decrements the current connection count.
// If c or pStats is nil, the original conn is returned unchanged.
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

// UnwrapConn returns the underlying connection, allowing type assertions
// through wrapper layers.
func (c *conn) UnwrapConn() net.Conn {
	return c.Conn
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

func (c *conn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *conn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}

func (c *conn) Context() context.Context {
	if innerCtx, ok := c.Conn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}

type packetConn struct {
	net.PacketConn
	stats stats.Stats
}

// WrapPacketConn wraps a net.PacketConn to track input and output bytes.
// If pc or stats is nil, the original conn is returned unchanged.
func WrapPacketConn(pc net.PacketConn, stats stats.Stats) net.PacketConn {
	if pc == nil || stats == nil {
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

func (c *packetConn) Context() context.Context {
	if innerCtx, ok := c.PacketConn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}

type udpConn struct {
	net.PacketConn
	stats  stats.Stats
	closed chan struct{}
	mu     sync.Mutex
}

// WrapUDPConn wraps a net.PacketConn as a udp.Conn to track connection and
// traffic statistics. It increments total and current connection counts (one
// accepted UDP client session == one connection, mirroring WrapConn) and
// tracks bytes read and written across all read/write methods (Read, Write,
// ReadFrom, WriteTo, ReadFromUDP, ReadMsgUDP, WriteToUDP, WriteMsgUDP). On
// Close, it decrements the current connection count.
//
// If pc is nil, nil is returned. If pStats is nil, the original connection
// is returned unchanged (consistent with WrapConn and WrapPacketConn).
func WrapUDPConn(pc net.PacketConn, pStats stats.Stats) udp.Conn {
	if pc == nil {
		return nil
	}
	if pStats == nil {
		if uc, ok := pc.(udp.Conn); ok {
			return uc
		}
		return nil
	}

	pStats.Add(stats.KindTotalConns, 1)
	pStats.Add(stats.KindCurrentConns, 1)

	return &udpConn{
		PacketConn: pc,
		stats:      pStats,
		closed:     make(chan struct{}),
	}
}

// Close decrements the current connection count once and closes the underlying
// PacketConn. It is safe to call multiple times.
func (c *udpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}

	c.stats.Add(stats.KindCurrentConns, -1)
	return c.PacketConn.Close()
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
		c.stats.Add(stats.KindInputBytes, int64(n))
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	c.stats.Add(stats.KindInputBytes, int64(n))
	return
}

func (c *udpConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		n, addr, err = nc.ReadFromUDP(b)
		c.stats.Add(stats.KindInputBytes, int64(n))
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		n, oobn, flags, addr, err = nc.ReadMsgUDP(b, oob)
		c.stats.Add(stats.KindInputBytes, int64(n))
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	if nc, ok := c.PacketConn.(io.Writer); ok {
		n, err = nc.Write(b)
		c.stats.Add(stats.KindOutputBytes, int64(n))
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	c.stats.Add(stats.KindOutputBytes, int64(n))
	return
}

func (c *udpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, err = nc.WriteToUDP(b, addr)
		c.stats.Add(stats.KindOutputBytes, int64(n))
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, oobn, err = nc.WriteMsgUDP(b, oob, addr)
		c.stats.Add(stats.KindOutputBytes, int64(n))
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

func (c *udpConn) Context() context.Context {
	if innerCtx, ok := c.PacketConn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}
