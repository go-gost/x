package ss

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
)

const (
	defaultBufferSize = 4096
)

var (
	_ net.PacketConn = (*UDPConn)(nil)
	_ net.Conn       = (*UDPConn)(nil)
)

// This wrapped connection has different behavior than ordinary connection:
// 1. ReadFrom will return target addr of shadowsocks instead of remote addr
type UDPConn struct {
	client     *core.UDPClient
	server     *core.UDPServer
	sessionMap *sync.Map
	net.PacketConn
	raddr      net.Addr
	taddr      net.Addr
	bufferSize int
}

func UDPClientConn(c net.PacketConn, remoteAddr, targetAddr net.Addr, bufferSize int, client *core.UDPClient, sessionMap *sync.Map) *UDPConn {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	return &UDPConn{
		PacketConn: c,
		raddr:      remoteAddr,
		taddr:      targetAddr,
		bufferSize: bufferSize,
		client:     client,
		sessionMap: sessionMap,
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := bufpool.Get(c.bufferSize)
	defer bufpool.Put(buf)

	clientAddr, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return
	}

	n, _, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	var payload []byte
	var session core.UDPSession
	if c.client != nil {
		s, ok := c.sessionMap.Load(core.SessionHashFromAddrPort(clientAddr))
		if !ok {
			return 0, nil, errors.New("udp session cannot find")
		}
		session = s.(core.UDPSession)
		payload, err = c.client.Outbound(buf[:n], session)
		if err != nil {
			return
		}
	} else {
		return 0, nil, errors.New("UDPConn must be client ")
	}

	n = copy(b, payload)
	addr, err = net.ResolveUDPAddr("udp", session.Target().String())

	return
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	target := socks.ParseAddr(c.taddr.String())
	clientAddr, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return
	}

	var session core.UDPSession
	var encrypted []byte
	if c.client != nil {
		session, encrypted, err = c.client.Inbound(b, clientAddr, target)
		if err != nil {
			return
		}
		c.sessionMap.Store(session.Hash(), session)
	} else {
		return 0, errors.New("UDPConn must be client")
	}

	_, err = c.PacketConn.WriteTo(encrypted, c.raddr)
	n = len(b)
	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.raddr
}
