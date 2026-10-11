package wrapper

import (
	"errors"
	"net"

	limiter "github.com/go-gost/core/limiter/conn"
)

// ErrConnLimit reports that a connection was refused because it exceeded the
// connection limit. It is a sentinel so callers can tell a single refused
// connection apart from a listener that has genuinely failed: the refusal is
// per-connection and leaves the listener usable, so it must not end an accept
// loop.
var ErrConnLimit = errors.New("connection limit exceeded")

type listener struct {
	net.Listener
	limiter limiter.ConnLimiter
}

// WrapListener wraps a net.Listener with a ConnLimiter. Each accepted
// connection is checked against the limiter using the remote IP as the key.
// If the limit is exceeded, the connection is closed with an error. If
// limiter is nil, the original listener is returned unchanged.
func WrapListener(limiter limiter.ConnLimiter, ln net.Listener) net.Listener {
	if limiter == nil {
		return ln
	}

	return &listener{
		limiter:  limiter,
		Listener: ln,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	if lim := ln.limiter.Limiter(host); lim != nil {
		if lim.Allow(1) {
			return WrapConn(lim, c), nil
		}
		c.Close()
		return nil, ErrConnLimit
	}

	return c, nil
}
