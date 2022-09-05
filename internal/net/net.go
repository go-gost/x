package net

import (
	"net"
	"syscall"
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
