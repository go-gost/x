package proxyproto

import (
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func WrapClientConn(ppv int, src, dst net.Addr, c net.Conn) net.Conn {
	if ppv <= 0 {
		return c
	}

	header := proxyproto.HeaderProxyFromAddrs(byte(ppv), src, dst)
	header.WriteTo(c)
	return c
}
