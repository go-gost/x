package wrapper

import (
	"net"

	"github.com/go-gost/core/observer/stats"
)

type listener struct {
	stats stats.Stats
	net.Listener
}

func WrapListener(ln net.Listener, stats stats.Stats) net.Listener {
	if stats == nil {
		return ln
	}

	return &listener{
		stats:    stats,
		Listener: ln,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return WrapConn(c, ln.stats), nil
}
