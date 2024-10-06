package net

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netns"
)

type SetBuffer interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

type SyscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

type RemoteAddr interface {
	RemoteAddr() net.Addr
}

// tcpraw.TCPConn
type SetDSCP interface {
	SetDSCP(int) error
}

func IsIPv4(address string) bool {
	return address != "" && address[0] != ':' && address[0] != '['
}

type ListenConfig struct {
	Netns string
	net.ListenConfig
}

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

type readWriteConnStats struct {
	TotalReadBytes  int
	TotalWriteBytes int
	lock            sync.Mutex
}
type readWriteConn struct {
	net.Conn
	r     io.Reader
	w     io.Writer
	Stats *readWriteConnStats
}

func NewReadWriteConn(r io.Reader, w io.Writer, c net.Conn) net.Conn {
	return &readWriteConn{
		Conn:  c,
		r:     r,
		w:     w,
		Stats: &readWriteConnStats{},
	}
}
func AssertReadWriteConn(conn net.Conn) (*readWriteConn, bool) {
	rwConn, ok := conn.(*readWriteConn)
	return rwConn, ok
}
func (c *readWriteConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == nil {
		c.addReadStat(n)
	}
	return n, err
}

func (c *readWriteConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil {
		c.addWriteStat(n)
	}
	return n, err
}
func (c *readWriteConn) addReadStat(val int) {
	c.Stats.lock.Lock()
	defer c.Stats.lock.Unlock()
	c.Stats.TotalReadBytes += val
}
func (c *readWriteConn) addWriteStat(val int) {
	c.Stats.lock.Lock()
	defer c.Stats.lock.Unlock()
	c.Stats.TotalWriteBytes += val
}
