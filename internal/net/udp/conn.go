package udp

import (
	"io"
	"net"

	xnet "github.com/go-gost/x/internal/net"
)

// Conn is a net.PacketConn that also supports io.Reader, io.Writer, buffer
// sizing, syscall access, and remote address exposure.
type Conn interface {
	net.PacketConn
	io.Reader
	io.Writer
	ReadUDP
	WriteUDP
	xnet.SetBuffer
	xnet.SyscallConn
	xnet.RemoteAddr
}

// ReadUDP supports reading UDP datagrams with metadata.
type ReadUDP interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

// WriteUDP supports writing UDP datagrams with metadata.
type WriteUDP interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}
