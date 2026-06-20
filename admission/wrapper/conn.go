package wrapper

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
)

var (
	errUnsupport = errors.New("unsupported operation")
)

// serverConn wraps a TCP connection (net.Conn) with per-read admission
// checking. Unlike the listener wrapper — which rejects at accept time —
// this wrapper re-validates the remote address on each Read call.
// This is useful when the admission rules may change during the lifetime
// of a connection, or when the connection was established before
// admission wrappers were applied.
type serverConn struct {
	net.Conn
	admission admission.Admission
}

// WrapConn wraps a net.Conn with per-read admission control.
// If admission is nil, the original connection is returned unchanged.
//
// When admission is denied on a Read, io.EOF is returned so the caller
// sees a clean end-of-stream rather than a hard error.
func WrapConn(admission admission.Admission, c net.Conn) net.Conn {
	if admission == nil {
		return c
	}
	return &serverConn{
		Conn:      c,
		admission: admission,
	}
}

// UnwrapConn returns the underlying connection, allowing type assertions
// through wrapper layers.
func (c *serverConn) UnwrapConn() net.Conn {
	return c.Conn
}

// Read checks the remote address against the admission controller
// before delegating to the underlying connection. If denied, it returns
// io.EOF to signal end-of-stream.
func (c *serverConn) Read(b []byte) (n int, err error) {
	if c.admission != nil &&
		!c.admission.Admit(context.Background(), c.RemoteAddr().Network(), c.RemoteAddr().String()) {
		err = io.EOF
		return
	}
	return c.Conn.Read(b)
}

// SyscallConn exposes the underlying raw connection for socket-level
// operations (e.g. setting SO_MARK, SO_REUSEPORT). Returns
// errUnsupport if the inner connection does not support this.
func (c *serverConn) SyscallConn() (rc syscall.RawConn, err error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		rc, err = sc.SyscallConn()
		return
	}
	err = errUnsupport
	return
}

// CloseRead shuts down the read side of the connection if supported.
func (c *serverConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

// CloseWrite shuts down the write side of the connection if supported.
func (c *serverConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}

// Context returns the context carried by the underlying connection,
// or nil if the connection does not carry context.
func (c *serverConn) Context() context.Context {
	if innerCtx, ok := c.Conn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}

// packetConn wraps a net.PacketConn with per-packet admission checking.
// Packets from denied addresses are silently dropped and the read
// loop continues to the next packet.
type packetConn struct {
	net.PacketConn
	admission admission.Admission
}

// WrapPacketConn wraps a net.PacketConn with per-packet admission control.
// If admission is nil, the original connection is returned unchanged.
//
// Denied packets are silently discarded; ReadFrom loops until it receives
// a packet from an allowed address or encounters an error.
func WrapPacketConn(admission admission.Admission, pc net.PacketConn) net.PacketConn {
	if admission == nil {
		return pc
	}
	return &packetConn{
		PacketConn: pc,
		admission:  admission,
	}
}

// ReadFrom reads the next packet from an admitted address. Packets from
// denied addresses are discarded and the method retries automatically.
func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		if c.admission != nil &&
			!c.admission.Admit(context.Background(), addr.Network(), addr.String()) {
			continue
		}

		return
	}
}

// Context returns the context carried by the underlying packet connection.
func (c *packetConn) Context() context.Context {
	if innerCtx, ok := c.PacketConn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}

// udpConn wraps a packet connection as a UDP-specific connection.
// It provides the same admission filtering as packetConn, plus UDP-
// specific operations (ReadFromUDP, ReadMsgUDP, WriteToUDP, WriteMsgUDP,
// SetDSCP, etc.).
//
// The wrapper delegates to optional interfaces on the underlying
// connection, returning errUnsupport if the capability is not available.
type udpConn struct {
	net.PacketConn
	admission admission.Admission
}

// WrapUDPConn wraps a net.PacketConn as a udp.Conn with admission control.
// This is used in UDP forwarding paths where the connection is treated
// as a connected UDP socket.
// If pc is nil, nil is returned. If admission is nil, the original connection
// is returned unchanged (no-op).
func WrapUDPConn(adm admission.Admission, pc net.PacketConn) udp.Conn {
	if pc == nil {
		return nil
	}
	if adm == nil {
		if uc, ok := pc.(udp.Conn); ok {
			return uc
		}
	}
	return &udpConn{
		PacketConn: pc,
		admission:  adm,
	}
}

// RemoteAddr returns the remote address from the underlying connection
// if it implements the RemoteAddr interface. This is used for "connected"
// UDP sockets that have a fixed peer.
func (c *udpConn) RemoteAddr() net.Addr {
	if nc, ok := c.PacketConn.(xnet.RemoteAddr); ok {
		return nc.RemoteAddr()
	}
	return nil
}

// SetReadBuffer sets the socket receive buffer size.
func (c *udpConn) SetReadBuffer(n int) error {
	if nc, ok := c.PacketConn.(xnet.SetBuffer); ok {
		return nc.SetReadBuffer(n)
	}
	return errUnsupport
}

// SetWriteBuffer sets the socket send buffer size.
func (c *udpConn) SetWriteBuffer(n int) error {
	if nc, ok := c.PacketConn.(xnet.SetBuffer); ok {
		return nc.SetWriteBuffer(n)
	}
	return errUnsupport
}

// Read delegates to the underlying connection's Read method if available
// (for connected UDP sockets that support stream-like reads).
func (c *udpConn) Read(b []byte) (n int, err error) {
	if nc, ok := c.PacketConn.(io.Reader); ok {
		n, err = nc.Read(b)
		return
	}
	err = errUnsupport
	return
}

// ReadFrom reads the next packet from an admitted address, discarding
// packets from denied addresses.
func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}
		if c.admission != nil &&
			!c.admission.Admit(context.Background(), addr.Network(), addr.String()) {
			continue
		}
		return
	}
}

// ReadFromUDP reads the next UDP packet from an admitted address.
// Packets from denied addresses are discarded transparently.
func (c *udpConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		for {
			n, addr, err = nc.ReadFromUDP(b)
			if err != nil {
				return
			}
			if c.admission != nil &&
				!c.admission.Admit(context.Background(), addr.Network(), addr.String()) {
				continue
			}
			return
		}
	}
	err = errUnsupport
	return
}

// ReadMsgUDP reads a UDP packet with out-of-band data from an admitted
// address. Packets from denied addresses are silently skipped.
func (c *udpConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if nc, ok := c.PacketConn.(udp.ReadUDP); ok {
		for {
			n, oobn, flags, addr, err = nc.ReadMsgUDP(b, oob)
			if err != nil {
				return
			}
			if c.admission != nil &&
				!c.admission.Admit(context.Background(), addr.Network(), addr.String()) {
				continue
			}
			return
		}
	}
	err = errUnsupport
	return
}

// Write delegates to the underlying connection's Write method if available
// (for connected UDP sockets).
func (c *udpConn) Write(b []byte) (n int, err error) {
	if nc, ok := c.PacketConn.(io.Writer); ok {
		n, err = nc.Write(b)
		return
	}
	err = errUnsupport
	return
}

// WriteTo sends a packet to the specified address via the underlying
// packet connection. No admission check is performed on writes.
func (c *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	return
}

// WriteToUDP sends a UDP packet to the specified address if the
// underlying connection supports UDP-specific writes.
func (c *udpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, err = nc.WriteToUDP(b, addr)
		return
	}
	err = errUnsupport
	return
}

// WriteMsgUDP sends a UDP packet with out-of-band data if supported.
func (c *udpConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if nc, ok := c.PacketConn.(udp.WriteUDP); ok {
		n, oobn, err = nc.WriteMsgUDP(b, oob, addr)
		return
	}
	err = errUnsupport
	return
}

// SyscallConn exposes the underlying raw connection for socket-level
// operations if supported.
func (c *udpConn) SyscallConn() (rc syscall.RawConn, err error) {
	if nc, ok := c.PacketConn.(xnet.SyscallConn); ok {
		return nc.SyscallConn()
	}
	err = errUnsupport
	return
}

// SetDSCP sets the Differentiated Services Code Point on the socket
// for traffic classification/QoS. Silently succeeds if not supported
// (best-effort).
func (c *udpConn) SetDSCP(n int) error {
	if nc, ok := c.PacketConn.(xnet.SetDSCP); ok {
		return nc.SetDSCP(n)
	}
	return nil
}

// Context returns the context carried by the underlying packet connection.
func (c *udpConn) Context() context.Context {
	if innerCtx, ok := c.PacketConn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return nil
}
