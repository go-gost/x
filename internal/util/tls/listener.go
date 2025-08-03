package tls

import (
	"crypto/tls"
	"net"

	"github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
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

func (c *tlsConn) Metadata() metadata.Metadata {
	if md, ok := c.NetConn().(metadata.Metadatable); ok {
		return md.Metadata()
	}
	return nil
}

func (c *tlsConn) SrcAddr() net.Addr {
	if sc, ok := c.NetConn().(xnet.SrcAddr); ok {
		return sc.SrcAddr()
	}
	return nil
}

func (c *tlsConn) DstAddr() net.Addr {
	if sc, ok := c.NetConn().(xnet.DstAddr); ok {
		return sc.DstAddr()
	}
	return nil
}
