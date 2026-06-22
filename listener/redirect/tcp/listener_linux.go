package tcp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (l *redirectListener) control(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		if l.md.tproxy {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
				l.logger.Errorf("failed to set IP_TRANSPARENT: %v", err)
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
				l.logger.Errorf("failed to set IPV6_TRANSPARENT: %v", err)
			}
		}
		if l.md.reuseport {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				l.logger.Errorf("failed to set SO_REUSEPORT: %v", err)
			}
		}
	})
}
