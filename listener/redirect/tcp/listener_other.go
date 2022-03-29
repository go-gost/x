//go:build !linux

package tcp

import (
	"errors"
	"syscall"
)

func (l *redirectListener) control(network, address string, c syscall.RawConn) error {
	return errors.New("TProxy is not available on non-linux platform")
}
