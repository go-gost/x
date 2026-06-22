package tcp

import (
	"errors"
	"syscall"
)

func (l *redirectListener) control(network, address string, c syscall.RawConn) error {
	if l.md.tproxy {
		return errors.New("TProxy is not available on non-linux platform")
	}
	// SO_REUSEADDR is the default on Windows, so reuseport is a no-op.
	return nil
}
