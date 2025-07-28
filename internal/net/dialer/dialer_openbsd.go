package dialer

import (
	"golang.org/x/sys/unix"
)

func bindDevice(network, address string, fd uintptr, ifceName string) error {
	return nil
}

func setMark(fd uintptr, mark int) error {
	if mark != 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RTABLE, mark)
}
