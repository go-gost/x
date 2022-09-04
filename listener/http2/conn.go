package http2

import (
	"errors"
	"net"
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
)

// a dummy HTTP2 server conn used by HTTP2 handler
type conn struct {
	md     mdata.Metadata
	r      *http.Request
	w      http.ResponseWriter
	laddr  net.Addr
	raddr  net.Addr
	closed chan struct{}
}

func (c *conn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "http2", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *conn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "http2", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *conn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Done() <-chan struct{} {
	return c.closed
}

// Metadata implements metadata.Metadatable interface.
func (c *conn) Metadata() mdata.Metadata {
	return c.md
}
