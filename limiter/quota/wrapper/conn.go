package wrapper

import (
	"context"
	"net"
	"syscall"

	"github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	"github.com/go-gost/x/limiter/quota"
	"github.com/go-gost/x/registry"
)

type quotaConn struct {
	net.Conn
	name string
}

func WrapConn(c net.Conn, name string) net.Conn {
	if c == nil || name == "" {
		return c
	}
	return &quotaConn{Conn: c, name: name}
}

func (c *quotaConn) Read(b []byte) (n int, err error) {
	lim := registry.QuotaLimiterRegistry().Get(c.name)
	if lim != nil && lim.Blocked() {
		return 0, quota.ErrQuotaExceeded
	}
	n, err = c.Conn.Read(b)
	if lim != nil && n > 0 {
		lim.AddIn(n)
	}
	return
}

func (c *quotaConn) Write(b []byte) (n int, err error) {
	lim := registry.QuotaLimiterRegistry().Get(c.name)
	if lim != nil && lim.Blocked() {
		return 0, quota.ErrQuotaExceeded
	}
	n, err = c.Conn.Write(b)
	if lim != nil && n > 0 {
		lim.AddOut(n)
	}
	return
}

// Forward optional capabilities so wrapping does not hide them from handlers.

func (c *quotaConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, xio.ErrUnsupported
}

func (c *quotaConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *quotaConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}

func (c *quotaConn) Context() context.Context {
	if cc, ok := c.Conn.(ctx.Context); ok {
		return cc.Context()
	}
	return nil
}

// UnwrapConn returns the underlying connection, allowing type assertions
// in handlers that iterate wrapper layers (e.g., SSH handler's unwrapConn).
func (c *quotaConn) UnwrapConn() net.Conn {
	return c.Conn
}
