package wrapper

import (
	"net"

	"github.com/go-gost/core/limiter"
)

type listener struct {
	net.Listener
	rlimiter limiter.RateLimiter
}

func WrapListener(rlimiter limiter.RateLimiter, ln net.Listener) net.Listener {
	if rlimiter == nil {
		return ln
	}

	return &listener{
		rlimiter: rlimiter,
		Listener: ln,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return WrapConn(ln.rlimiter, c), nil
}
