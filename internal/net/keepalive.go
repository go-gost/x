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

// ApplyNoDelay disables Nagle's algorithm on conn if it is a *net.TCPConn.
//
// gost tunnels carry small, latency-sensitive datagrams (e.g. WireGuard UDP
// over relay+ws/wss). Without this, Nagle coalesces each frame until a peer
// ACK returns, adding up to one RTT per datagram — the root cause of the
// latency regression reported in go-gost/gost#858. Match wstunnel, which sets
// TCP_NODELAY on its tunnel socket by default.
func ApplyNoDelay(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
}

// WrapNoDelayListener wraps ln so that TCP_NODELAY is applied to every accepted
// *net.TCPConn before it enters the middleware wrapper chain.
func WrapNoDelayListener(ln net.Listener) net.Listener {
	return &noDelayListener{Listener: ln}
}

type noDelayListener struct {
	net.Listener
}

func (l *noDelayListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ApplyNoDelay(conn)
	return conn, nil
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
