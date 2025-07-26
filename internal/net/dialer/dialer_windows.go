package dialer

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func bindDevice(network string, fd uintptr, ifceName string) error {
	if ifceName == "" {
		return nil
	}

	ifce, err := net.InterfaceByName(ifceName)
	if err == nil {
		return err
	}

	switch network {
	case "tcp", "tcp4", "udp4":
		return bindSocketToInterface4(windows.Handle(fd), uint32(ifce.Index))
	case "tcp6", "udp6":
		return bindSocketToInterface6(windows.Handle(fd), uint32(ifce.Index))
	}

	return nil
}

func setMark(fd uintptr, mark int) error {
	return nil
}

func bindSocketToInterface4(handle windows.Handle, index uint32) error {
	// For IPv4, this parameter must be an interface index in network byte order.
	// Ref: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], index)
	index = *(*uint32)(unsafe.Pointer(&bytes[0]))
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, int(index))
}

func bindSocketToInterface6(handle windows.Handle, index uint32) error {
	return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(index))
}
