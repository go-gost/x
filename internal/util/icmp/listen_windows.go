//go:build windows

package icmp

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/icmp"
)

// Windows-specific constants for WSAIoctl.
const (
	SIO_RCVALL = syscall.IOC_IN | syscall.IOC_VENDOR | 1

	RCVALL_OFF             = 0
	RCVALL_ON              = 1
	RCVALL_SOCKETLEVELONLY = 2
	RCVALL_IPLEVEL         = 3
)

// ListenPacket listens for ICMP packets on the given network and address.
// On Windows, when the address is unspecified ("" or "0.0.0.0"/"::"), it uses
// SIO_RCVALL to work around https://github.com/golang/go/issues/38427.
func ListenPacket(network, address string) (net.PacketConn, error) {
	if ip := net.ParseIP(address); ip != nil && !ip.IsUnspecified() {
		return icmp.ListenPacket(network, address)
	}

	dialAddr, dialNetwork := probeAddr(network)
	if dialAddr == "" {
		return icmp.ListenPacket(network, address)
	}

	// Dial an external address to discover the correct local interface.
	dialedConn, err := net.Dial(dialNetwork, dialAddr)
	if err != nil {
		return nil, fmt.Errorf("icmp: dial %s: %w", dialAddr, err)
	}
	localAddr := dialedConn.LocalAddr()
	dialedConn.Close()

	var socketHandle syscall.Handle
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(s uintptr) {
				socketHandle = syscall.Handle(s)
			})
		},
	}

	conn, err := cfg.ListenPacket(context.Background(), network, localAddr.String())
	if err != nil {
		return nil, err
	}

	// Enable promiscuous mode so the socket receives all ICMP packets,
	// including error messages, regardless of the original destination address.
	unused := uint32(0)
	flag := uint32(RCVALL_IPLEVEL)
	size := uint32(unsafe.Sizeof(flag))
	if err := syscall.WSAIoctl(socketHandle, SIO_RCVALL, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &unused, nil, 0); err != nil {
		conn.Close()
		return nil, fmt.Errorf("icmp: WSAIoctl(SIO_RCVALL): %w", os.NewSyscallError("WSAIoctl", err))
	}

	return conn, nil
}

// probeAddr returns the dial network and address to use for discovering
// the local interface. Returns empty strings if the network is not a
// supported ICMP type.
func probeAddr(network string) (dialAddr, dialNetwork string) {
	switch network {
	case "ip4:icmp":
		return "1.1.1.1", "ip4:icmp"
	case "ip6:ipv6-icmp":
		return "2001:4860:4860::8888", "ip6:ipv6-icmp"
	}
	return "", ""
}
