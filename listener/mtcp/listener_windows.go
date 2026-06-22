//go:build windows

package mtcp

import (
	"syscall"
)

func (l *mtcpListener) setReusePort(network, address string, c syscall.RawConn) error {
	return nil
}
