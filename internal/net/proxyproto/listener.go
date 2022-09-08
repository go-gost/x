package proxyproto

import (
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func WrapListener(ppv int, ln net.Listener, readHeaderTimeout time.Duration) net.Listener {
	if ppv <= 0 {
		return ln
	}

	return &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: readHeaderTimeout,
	}
}
