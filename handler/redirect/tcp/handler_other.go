//go:build !linux && !darwin

package redirect

import (
	"errors"
	"net"
)

func (h *redirectHandler) getOriginalDstAddr(_ net.Conn) (addr net.Addr, err error) {
	err = errors.New("TCP redirect is not available on non-linux platform")
	return
}
