//go:build !windows

package mtcp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (l *mtcpListener) setReusePort(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			l.logger.Errorf("failed to set SO_REUSEPORT: %v", err)
		}
	})
}
