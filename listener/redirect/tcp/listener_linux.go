package tcp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (l *redirectListener) control(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			l.logger.Errorf("SetsockoptInt(SOL_IP, IP_TRANSPARENT, 1): %v", err)
		}
	})
}
