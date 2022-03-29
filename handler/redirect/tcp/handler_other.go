//go:build !linux

package redirect

import (
	"errors"
	"net"
)

func (h *redirectHandler) getOriginalDstAddr(conn net.Conn) (addr net.Addr, err error) {
	err = errors.New("TCP redirect is not available on non-linux platform")
	return
}
