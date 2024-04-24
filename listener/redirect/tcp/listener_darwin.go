package tcp

import (
	"syscall"
)

func (l *redirectListener) control(network, address string, c syscall.RawConn) error {
	return nil
}
