package wrapper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"

	limiter "github.com/go-gost/core/limiter/traffic"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
)

var (
	errUnsupport = errors.New("unsupported operation")
)

// serverConn is a server side Conn with metrics supported.
type serverConn struct {
	net.Conn
	rbuf       bytes.Buffer
	limiterIn  limiter.Limiter
	limiterOut limiter.Limiter
}

func WrapConn(rlimiter limiter.TrafficLimiter, c net.Conn) net.Conn {
	if rlimiter == nil {
		return c
	}
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	return &serverConn{
		Conn:       c,
		limiterIn:  rlimiter.In(host),
		limiterOut: rlimiter.Out(host),
	}
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	if c.limiterIn == nil {
		return c.Conn.Read(b)
	}

	if c.rbuf.Len() > 0 {
		burst := len(b)
		if c.rbuf.Len() < burst {
			burst = c.rbuf.Len()
		}
		lim := c.limiterIn.Wait(context.Background(), burst)
		return c.rbuf.Read(b[:lim])
	}

	nn, err := c.Conn.Read(b)
	if err != nil {
		return nn, err
	}

	n = c.limiterIn.Wait(context.Background(), nn)
	if n < nn {
		if _, err = c.rbuf.Write(b[n:nn]); err != nil {
			return 0, err
		}
	}

	return
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if c.limiterOut == nil {
		return c.Conn.Write(b)
	}

	nn := 0
	for len(b) > 0 {
		nn, err = c.Conn.Write(b[:c.limiterOut.Wait(context.Background(), len(b))])
		n += nn
		if err != nil {
			return
		}
		b = b[nn:]
	}

	return
}

func (c *serverConn) SyscallConn() (rc syscall.RawConn, err error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		rc, err = sc.SyscallConn()
		return
	}
	err = errUnsupport
	return
}

type packetConn struct {
	net.PacketConn
	limiter   limiter.TrafficLimiter
	inLimits  map[string]limiter.Limiter
	inMux     sync.RWMutex
	outLimits map[string]limiter.Limiter
	outMux    sync.RWMutex
}

func WrapPacketConn(lim limiter.TrafficLimiter, pc net.PacketConn) net.PacketConn {
	if lim == nil {
		return pc
	}
	return &packetConn{
		PacketConn: pc,
		limiter:    lim,
		inLimits:   make(map[string]limiter.Limiter),
		outLimits:  make(map[string]limiter.Limiter),
	}
}

func (c *packetConn) getInLimiter(addr net.Addr) limiter.Limiter {
	if c.limiter == nil {
		return nil
	}

	lim, ok := func() (limiter.Limiter, bool) {
		c.inMux.RLock()
		defer c.inMux.RUnlock()

		lim, ok := c.inLimits[addr.String()]
		return lim, ok
	}()
	if ok {
		return lim
	}

	host, _, _ := net.SplitHostPort(addr.String())
	lim = c.limiter.In(host)

	c.inMux.Lock()
	defer c.inMux.Unlock()

	c.inLimits[addr.String()] = lim

	return lim
}

func (c *packetConn) getOutLimiter(addr net.Addr) limiter.Limiter {
	if c.limiter == nil {
		return nil
	}

	lim, ok := func() (limiter.Limiter, bool) {
		c.outMux.RLock()
		defer c.outMux.RUnlock()

		lim, ok := c.outLimits[addr.String()]
		return lim, ok
	}()
	if ok {
		return lim
	}

	host, _, _ := net.SplitHostPort(addr.String())
	lim = c.limiter.Out(host)

	c.outMux.Lock()
	defer c.outMux.Unlock()

	c.outLimits[addr.String()] = lim

	return lim
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		limiter := c.getInLimiter(addr)
		if limiter == nil {
			return
		}

		// discard when exceed the limit size.
		if limiter.Wait(context.Background(), n) < n {
			continue
		}

		return
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// discard when exceed the limit size.
	if limiter := c.getOutLimiter(addr); limiter != nil &&
		limiter.Wait(context.Background(), len(p)) < len(p) {
		n = len(p)
		return
	}

	return c.PacketConn.WriteTo(p, addr)
}

type udpConn struct {
	net.PacketConn
	limiter   limiter.TrafficLimiter
	inLimits  map[string]limiter.Limiter
	inMux     sync.RWMutex
	outLimits map[string]limiter.Limiter
	outMux    sync.RWMutex
}

func WrapUDPConn(limiter limiter.TrafficLimiter, pc net.PacketConn) udp.Conn {
	return &udpConn{
		PacketConn: pc,
		limiter:    limiter,
	}
}

func (c *udpConn) getInLimiter(addr net.Addr) limiter.Limiter {
	if c.limiter == nil {
		return nil
	}

	lim, ok := func() (limiter.Limiter, bool) {
		c.inMux.RLock()
		defer c.inMux.RUnlock()

		lim, ok := c.inLimits[addr.String()]
		return lim, ok
	}()
	if ok {
		return lim
	}

	host, _, _ := net.SplitHostPort(addr.String())
	lim = c.limiter.In(host)

	c.inMux.Lock()
	defer c.inMux.Unlock()

	c.inLimits[addr.String()] = lim

	return lim
}

func (c *udpConn) getOutLimiter(addr net.Addr) limiter.Limiter {
	if c.limiter == nil {
		return nil
	}

	lim, ok := func() (limiter.Limiter, bool) {
		c.outMux.RLock()
		defer c.outMux.RUnlock()

		lim, ok := c.outLimits[addr.String()]
		return lim, ok
	}()
	if ok {
		return lim
	}

	host, _, _ := net.SplitHostPort(addr.String())
	lim = c.limiter.Out(host)

	c.outMux.Lock()
	defer c.outMux.Unlock()

	c.outLimits[addr.String()] = lim

	return lim
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
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		// discard when exceed the limit size.
		if limiter := c.getInLimiter(addr); limiter != nil &&
			limiter.Wait(context.Background(), n) < n {
			continue
		}
		return
	}
}

func (c *udpConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		for {
			n, addr, err = nc.ReadFromUDP(b)
			if err != nil {
				return
			}

			// discard when exceed the limit size.
			if limiter := c.getInLimiter(addr); limiter != nil &&
				limiter.Wait(context.Background(), n) < n {
				continue
			}
			return
		}
	}
	err = errUnsupport
	return
}

func (c *udpConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		for {
			n, oobn, flags, addr, err = nc.ReadMsgUDP(b, oob)
			if err != nil {
				return
			}

			// discard when exceed the limit size.
			if limiter := c.getInLimiter(addr); limiter != nil &&
				limiter.Wait(context.Background(), n) < n {
				continue
			}
			return
		}
	}
	err = errUnsupport
	return
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	if nc, ok := c.PacketConn.(io.Writer); ok {
		n, err = nc.Write(b)
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// discard when exceed the limit size.
	if limiter := c.getOutLimiter(addr); limiter != nil &&
		limiter.Wait(context.Background(), len(p)) < len(p) {
		n = len(p)
		return
	}

	n, err = c.PacketConn.WriteTo(p, addr)
	return
}

func (c *udpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	// discard when exceed the limit size.
	if limiter := c.getOutLimiter(addr); limiter != nil &&
		limiter.Wait(context.Background(), len(b)) < len(b) {
		n = len(b)
		return
	}

	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, err = nc.WriteToUDP(b, addr)
		return
	}
	err = errUnsupport
	return
}

func (c *udpConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	// discard when exceed the limit size.
	if limiter := c.getOutLimiter(addr); limiter != nil &&
		limiter.Wait(context.Background(), len(b)) < len(b) {
		n = len(b)
		return
	}

	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, oobn, err = nc.WriteMsgUDP(b, oob, addr)
		return
	}
	err = errUnsupport
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
