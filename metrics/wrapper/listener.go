package wrapper

import (
	"net"
)

type listener struct {
	service string
	net.Listener
}

// WrapListener wraps a net.Listener so that all accepted connections are
// automatically wrapped with WrapConn for metrics tracking. If ln is nil,
// nil is returned.
func WrapListener(service string, ln net.Listener) net.Listener {
	if ln == nil {
		return ln
	}
	return &listener{
		service:  service,
		Listener: ln,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return WrapConn(ln.service, c), nil
}
