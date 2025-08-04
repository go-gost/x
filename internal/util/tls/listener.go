package tls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/go-gost/x/ctx"
)

type listener struct {
	net.Listener
	config *tls.Config
}

func NewListener(inner net.Listener, config *tls.Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsConn{
		Conn: tls.Server(c, l.config),
	}, nil
}

type tlsConn struct {
	*tls.Conn
}

func (c *tlsConn) Context() context.Context {
	if sc, ok := c.NetConn().(ctx.Context); ok {
		return sc.Context()
	}
	return nil
}
