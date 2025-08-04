package proxyproto

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/x/ctx"
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

	innerCtx := context.Background()
	if c, ok := conn.(ctx.Context); ok {
		if v := c.Context(); v != nil {
			innerCtx = v
		}
	}

	innerCtx = ctx.ContextWithSrcAddr(innerCtx, conn.RemoteAddr())
	innerCtx = ctx.ContextWithDstAddr(innerCtx, conn.LocalAddr())

	return &serverConn{Conn: conn, ctx: innerCtx}, nil
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
