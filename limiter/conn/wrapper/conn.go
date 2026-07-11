// Package wrapper provides net.Conn and net.Listener wrappers that enforce
// connection limits.
package wrapper

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"

	limiter "github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
)

var (
	errUnsupport = errors.New("unsupported operation")
)

// serverConn is a server side Conn with metrics supported.
type serverConn struct {
	net.Conn
	limiter limiter.Limiter
	closed  atomic.Bool // release the limiter slot once, even if Close is called more than once
}

// WrapConn wraps a net.Conn with a connection limiter. On Close, the
// limiter's Allow(-1) is called to decrement the current count. If limiter
// is nil, the original connection is returned unchanged.
func WrapConn(limiter limiter.Limiter, c net.Conn) net.Conn {
	if limiter == nil {
		return c
	}
	return &serverConn{
		Conn:    c,
		limiter: limiter,
	}
}

// UnwrapConn returns the underlying connection, allowing type assertions
// through wrapper layers.
func (c *serverConn) UnwrapConn() net.Conn {
	return c.Conn
}

func (c *serverConn) SyscallConn() (rc syscall.RawConn, err error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		rc, err = sc.SyscallConn()
		return
	}
	err = errUnsupport
	return
}

func (c *serverConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.limiter.Allow(-1)
	}
	return c.Conn.Close()
}

func (c *serverConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *serverConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}

func (c *serverConn) Context() context.Context {
	if innerCtx, ok := c.Conn.(ctx.Context); ok {
		return innerCtx.Context()
	}
	return context.Background()
}
