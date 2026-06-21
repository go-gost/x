package wrapper

import (
	"net"

	xmetrics "github.com/go-gost/x/metrics"
)

type listener struct {
	service string
	net.Listener
}

// WrapListener wraps a net.Listener so that all accepted connections are
// automatically wrapped with WrapConn for metrics tracking. If metrics are
// not enabled, ln is returned unchanged to allow splice(2) optimization
// on bare *net.TCPConn. If ln is nil, nil is returned.
func WrapListener(service string, ln net.Listener) net.Listener {
	if ln == nil || !xmetrics.IsEnabled() {
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
