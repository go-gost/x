package net

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"syscall"

	xio "github.com/go-gost/x/internal/io"
	"github.com/vishvananda/netns"
)

// SetBuffer is a connection that supports setting send and receive buffer sizes.
type SetBuffer interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// SyscallConn is a connection that exposes its raw system file descriptor.
type SyscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// RemoteAddr is a connection that exposes its remote address.
type RemoteAddr interface {
	RemoteAddr() net.Addr
}

// SetDSCP is a connection that supports setting the DSCP field.
type SetDSCP interface {
	SetDSCP(int) error
}

// IsIPv4 reports whether address is an IPv4 address by checking whether
// it starts with ':' or '[' (IPv6) vs a digit (IPv4).
func IsIPv4(address string) bool {
	return address != "" && address[0] != ':' && address[0] != '['
}

// ListenConfig extends net.ListenConfig with network namespace support.
type ListenConfig struct {
	Netns string
	net.ListenConfig
}

// Listen announces on the local network address, switching into the configured
// network namespace first if one is set.
func (lc *ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if lc.Netns != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		originNs, err := netns.Get()
		if err != nil {
			return nil, fmt.Errorf("netns.Get(): %v", err)
		}
		defer netns.Set(originNs)

		var ns netns.NsHandle
		if strings.HasPrefix(lc.Netns, "/") {
			ns, err = netns.GetFromPath(lc.Netns)
		} else {
			ns, err = netns.GetFromName(lc.Netns)
		}
		if err != nil {
			return nil, fmt.Errorf("netns.Get(%s): %v", lc.Netns, err)
		}
		defer ns.Close()

		if err := netns.Set(ns); err != nil {
			return nil, fmt.Errorf("netns.Set(%s): %v", lc.Netns, err)
		}
	}

	return lc.ListenConfig.Listen(ctx, network, address)
}

// ListenPacket announces on the local network address for packet connections,
// switching into the configured network namespace first if one is set.
func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if lc.Netns != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		originNs, err := netns.Get()
		if err != nil {
			return nil, fmt.Errorf("netns.Get(): %v", err)
		}
		defer netns.Set(originNs)

		var ns netns.NsHandle
		if strings.HasPrefix(lc.Netns, "/") {
			ns, err = netns.GetFromPath(lc.Netns)
		} else {
			ns, err = netns.GetFromName(lc.Netns)
		}
		if err != nil {
			return nil, fmt.Errorf("netns.Get(%s): %v", lc.Netns, err)
		}
		defer ns.Close()

		if err := netns.Set(ns); err != nil {
			return nil, fmt.Errorf("netns.Set(%s): %v", lc.Netns, err)
		}
	}
	return lc.ListenConfig.ListenPacket(ctx, network, address)
}

type readWriteConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

// NewReadWriteConn returns a net.Conn that reads from r and writes to w,
// delegating all other operations to c. If c supports CloseRead or CloseWrite,
// those are forwarded; otherwise they return ErrUnsupported.
func NewReadWriteConn(r io.Reader, w io.Writer, c net.Conn) net.Conn {
	return &readWriteConn{
		Conn: c,
		r:    r,
		w:    w,
	}
}

func (c *readWriteConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *readWriteConn) Write(p []byte) (int, error) {
	return c.w.Write(p)
}

func (c *readWriteConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *readWriteConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}
