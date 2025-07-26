package dialer

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
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
		return unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifce.Index)
	case "tcp6", "udp6":
		return unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifce.Index)
	}

	return nil
}

func setMark(fd uintptr, mark int) error {
	return nil
}
