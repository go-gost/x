package dialer

import (
	"golang.org/x/sys/unix"
)

func bindDevice(fd uintptr, ifceName string) error {
	if ifceName == "" {
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
