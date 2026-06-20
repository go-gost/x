// Package wrapper provides net.Conn, net.PacketConn, and io.ReadWriter
// wrappers that apply traffic rate limiting to reads and writes.
package wrapper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
)

var (
	errUnsupport   = errors.New("unsupported operation")
	errRateLimited = errors.New("rate limited")
)

// ErrRateLimited is returned when a write exceeds the rate limit.
var ErrRateLimited = errRateLimited

// DroppedPacketCounter is an optional interface implemented by rate-limited
// packet connections that report the number of packets discarded due to rate
// limiting.
type DroppedPacketCounter interface {
	DroppedPackets() int64
}

// limitConn wraps a net.Conn with traffic rate limiting applied to reads and writes.
type limitConn struct {
	net.Conn
	rbuf    bytes.Buffer
	limiter traffic.TrafficLimiter
	opts    []limiter.Option
	key     string
}

// WrapConn wraps a net.Conn with traffic rate limiting. If tlimiter is nil,
// the original conn is returned unchanged.
func WrapConn(c net.Conn, tlimiter traffic.TrafficLimiter, key string, opts ...limiter.Option) net.Conn {
	if tlimiter == nil {
		return c
	}

	return &limitConn{
		Conn:    c,
		limiter: tlimiter,
		opts:    opts,
		key:     key,
	}
}

func (c *limitConn) Read(b []byte) (n int, err error) {
	limiter := c.limiter.In(context.Background(), c.key, c.opts...)
	if limiter == nil || limiter.Limit() <= 0 {
		return c.Conn.Read(b)
	}

	if c.rbuf.Len() > 0 {
		burst := len(b)
		if c.rbuf.Len() < burst {
			burst = c.rbuf.Len()
		}
		lim := limiter.Wait(context.Background(), burst)
		return c.rbuf.Read(b[:lim])
	}

	nn, err := c.Conn.Read(b)
	if err != nil {
		return nn, err
	}

	n = limiter.Wait(context.Background(), nn)
	if n < nn {
		if _, err = c.rbuf.Write(b[n:nn]); err != nil {
			return 0, err
		}
	}

	return
}

func (c *limitConn) Write(b []byte) (n int, err error) {
	limiter := c.limiter.Out(context.Background(), c.key, c.opts...)
	if limiter == nil || limiter.Limit() <= 0 {
		return c.Conn.Write(b)
	}

	nn := 0
	for len(b) > 0 {
		burst := limiter.Wait(context.Background(), len(b))
		if burst == 0 {
			return
		}
		nn, err = c.Conn.Write(b[:burst])
		n += nn
		if err != nil {
			return
		}
		b = b[nn:]
	}

	return
}

// UnwrapConn returns the underlying connection, allowing type assertions
// through wrapper layers.
func (c *limitConn) UnwrapConn() net.Conn {
	return c.Conn
}

func (c *limitConn) SyscallConn() (rc syscall.RawConn, err error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		rc, err = sc.SyscallConn()
		return
	}
	err = errUnsupport
	return
}

func (c *limitConn) Context() context.Context {
	if innerCtx, ok := c.Conn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}

func (c *limitConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *limitConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}

type packetConn struct {
	net.PacketConn
	limiter traffic.TrafficLimiter
	opts    []limiter.Option
	key     string
	dropped atomic.Int64
}

// DroppedPackets returns the number of packets discarded due to rate limiting.
func (c *packetConn) DroppedPackets() int64 {
	return c.dropped.Load()
}

// WrapPacketConn wraps a net.PacketConn with traffic rate limiting. Packets
// exceeding the rate limit are discarded on read or rejected with an error on write.
func WrapPacketConn(pc net.PacketConn, lim traffic.TrafficLimiter, key string, opts ...limiter.Option) net.PacketConn {
	if lim == nil {
		return pc
	}
	return &packetConn{
		PacketConn: pc,
		limiter:    lim,
		opts:       opts,
		key:        key,
	}
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		limiter := c.limiter.In(context.Background(), c.key, c.opts...)
		if limiter == nil || limiter.Limit() <= 0 {
			return
		}

		// discard when exceed the limit size.
		if limiter.Wait(context.Background(), n) < n {
			c.dropped.Add(1)
			continue
		}

		return
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	limiter := c.limiter.Out(context.Background(), c.key, c.opts...)
	if limiter != nil && limiter.Limit() > 0 &&
		limiter.Wait(context.Background(), len(p)) < len(p) {
		return 0, ErrRateLimited
	}

	return c.PacketConn.WriteTo(p, addr)
}

func (c *packetConn) Context() context.Context {
	if innerCtx, ok := c.PacketConn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}

type udpConn struct {
	net.PacketConn
	limiter traffic.TrafficLimiter
	opts    []limiter.Option
	key     string
	dropped atomic.Int64
}

// DroppedPackets returns the number of packets discarded due to rate limiting.
func (c *udpConn) DroppedPackets() int64 {
	return c.dropped.Load()
}

// WrapUDPConn wraps a net.PacketConn as a udp.Conn with traffic rate limiting.
// If pc is nil, nil is returned. If limiter is nil, the original connection is
// returned unchanged (no-op).
func WrapUDPConn(pc net.PacketConn, lim traffic.TrafficLimiter, key string, opts ...limiter.Option) udp.Conn {
	if pc == nil {
		return nil
	}
	if lim == nil {
		if uc, ok := pc.(udp.Conn); ok {
			return uc
		}
	}
	return &udpConn{
		PacketConn: pc,
		limiter:    lim,
		opts:       opts,
		key:        key,
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
	nc, ok := c.PacketConn.(io.Reader)
	if !ok {
		err = errUnsupport
		return
	}

	for {
		n, err = nc.Read(b)
		if err != nil {
			return
		}

		if c.limiter == nil {
			return
		}

		limiter := c.limiter.In(context.Background(), c.key, c.opts...)
		if limiter == nil || limiter.Limit() <= 0 {
			return
		}

		// discard when exceed the limit size.
		if limiter.Wait(context.Background(), n) < n {
			c.dropped.Add(1)
			continue
		}

		return
	}
}

func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		if c.limiter == nil {
			return
		}

		limiter := c.limiter.In(context.Background(), c.key, c.opts...)
		if limiter == nil || limiter.Limit() <= 0 {
			return
		}

		// discard when exceed the limit size.
		if limiter.Wait(context.Background(), n) < n {
			c.dropped.Add(1)
			continue
		}

		return
	}
}

func (c *udpConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	nc, ok := c.PacketConn.(udp.ReadUDP)
	if !ok {
		err = errUnsupport
		return
	}

	for {
		n, addr, err = nc.ReadFromUDP(b)
		if err != nil {
			return
		}

		if c.limiter == nil {
			return
		}

		limiter := c.limiter.In(context.Background(), c.key, c.opts...)
		if limiter == nil || limiter.Limit() <= 0 {
			return
		}

		// discard when exceed the limit size.
		if limiter.Wait(context.Background(), n) < n {
			c.dropped.Add(1)
			continue
		}

		return
	}
}

func (c *udpConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	nc, ok := c.PacketConn.(udp.ReadUDP)
	if !ok {
		err = errUnsupport
		return
	}

	for {
		n, oobn, flags, addr, err = nc.ReadMsgUDP(b, oob)
		if err != nil {
			return
		}

		if c.limiter == nil {
			return
		}

		limiter := c.limiter.In(context.Background(), c.key, c.opts...)
		if limiter == nil || limiter.Limit() <= 0 {
			return
		}

		// discard when exceed the limit size.
		if limiter.Wait(context.Background(), n) < n {
			c.dropped.Add(1)
			continue
		}
		return
	}
}

func (c *udpConn) Write(p []byte) (n int, err error) {
	nc, ok := c.PacketConn.(io.Writer)
	if !ok {
		err = errUnsupport
		return
	}

	if c.limiter != nil {
		limiter := c.limiter.Out(context.Background(), c.key, c.opts...)
		if limiter != nil && limiter.Limit() > 0 &&
			limiter.Wait(context.Background(), len(p)) < len(p) {
			return 0, ErrRateLimited
		}
	}

	n, err = nc.Write(p)
	return
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.limiter != nil {
		limiter := c.limiter.Out(context.Background(), c.key, c.opts...)
		if limiter != nil && limiter.Limit() > 0 &&
			limiter.Wait(context.Background(), len(p)) < len(p) {
			return 0, ErrRateLimited
		}
	}

	n, err = c.PacketConn.WriteTo(p, addr)
	return
}

func (c *udpConn) WriteToUDP(p []byte, addr *net.UDPAddr) (n int, err error) {
	nc, ok := c.PacketConn.(udp.WriteUDP)
	if !ok {
		err = errUnsupport
		return
	}

	if c.limiter != nil {
		limiter := c.limiter.Out(context.Background(), c.key, c.opts...)
		if limiter != nil && limiter.Limit() > 0 &&
			limiter.Wait(context.Background(), len(p)) < len(p) {
			return 0, ErrRateLimited
		}
	}

	n, err = nc.WriteToUDP(p, addr)
	return
}

func (c *udpConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	nc, ok := c.PacketConn.(udp.WriteUDP)
	if !ok {
		err = errUnsupport
		return
	}

	if c.limiter != nil {
		limiter := c.limiter.Out(context.Background(), c.key, c.opts...)
		if limiter != nil && limiter.Limit() > 0 &&
			limiter.Wait(context.Background(), len(p)) < len(p) {
			return 0, 0, ErrRateLimited
		}
	}

	n, oobn, err = nc.WriteMsgUDP(p, oob, addr)
	return
}

func (c *udpConn) SyscallConn() (rc syscall.RawConn, err error) {
	if nc, ok := c.PacketConn.(xnet.SyscallConn); ok {
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
