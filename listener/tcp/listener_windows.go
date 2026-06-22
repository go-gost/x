//go:build windows

package tcp

import (
	"syscall"
)

func (l *tcpListener) setReusePort(network, address string, c syscall.RawConn) error {
	return nil
}
