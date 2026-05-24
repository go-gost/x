package wrapper

import (
	"net"

	"github.com/go-gost/core/observer/stats"
)

type listener struct {
	stats stats.Stats
	net.Listener
}

// WrapListener wraps a net.Listener to track connection statistics. Each
// accepted connection is wrapped via WrapConn to count connections and bytes.
// If ln or stats is nil, the original listener is returned unchanged.
func WrapListener(ln net.Listener, stats stats.Stats) net.Listener {
	if ln == nil || stats == nil {
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
