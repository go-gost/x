package net

import "net"

// WrapKeepaliveListener wraps ln so that TCP keepalive config is applied to
// every accepted *net.TCPConn before it enters the middleware wrapper chain.
func WrapKeepaliveListener(ln net.Listener, cfg net.KeepAliveConfig) net.Listener {
	return &keepaliveListener{Listener: ln, cfg: cfg}
}

// ApplyKeepalive applies cfg to conn if it is a *net.TCPConn.
func ApplyKeepalive(conn net.Conn, cfg net.KeepAliveConfig) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAliveConfig(cfg)
	}
}

type keepaliveListener struct {
	net.Listener
	cfg net.KeepAliveConfig
}

func (l *keepaliveListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAliveConfig(l.cfg)
	}
	return conn, nil
}
