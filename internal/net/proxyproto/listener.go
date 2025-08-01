package proxyproto

import (
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

type listener struct {
	net.Listener
}

func (ln *listener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &serverConn{Conn: conn}, nil
}

func WrapListener(ppv int, ln net.Listener, readHeaderTimeout time.Duration) net.Listener {
	if ppv <= 0 {
		return ln
	}

	return &listener{
		Listener: &proxyproto.Listener{
			Listener:          ln,
			ReadHeaderTimeout: readHeaderTimeout,
		},
	}
}
