package dialer

import (
	"net"

	"golang.org/x/sys/unix"
)

func bindDevice(network, address string, fd uintptr, ifceName string) error {
	if ifceName == "" {
		return nil
	}

	// Skip SO_BINDTODEVICE for loopback interface — it prevents
	// outbound traffic from reaching non-local destinations.
	// Source IP binding via LocalAddr is sufficient for policy routing
	// when using IP aliases on loopback (e.g. ip addr add 10.1.1.1/32 dev lo).
	if ifce, err := net.InterfaceByName(ifceName); err == nil && ifce.Flags&net.FlagLoopback != 0 {
		return nil
	}

	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
		return nil
	}

	return unix.BindToDevice(int(fd), ifceName)
}

func setMark(fd uintptr, mark int) error {
	if mark == 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
}
