//go:build !linux && !darwin && !windows

package tcp

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func (l *redirectListener) control(network, address string, c syscall.RawConn) error {
	if l.md.tproxy {
		return errors.New("TProxy is not available on non-linux platform")
	}
	if l.md.reuseport {
		return c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				l.logger.Errorf("failed to set SO_REUSEPORT: %v", err)
			}
		})
	}
	return nil
}
