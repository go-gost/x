package http2

import (
	"errors"
	"net"
	"time"

	mdata "github.com/go-gost/core/metadata"
)

// a dummy HTTP2 client conn used by HTTP2 client connector
type conn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	onClose    func()
	md         mdata.Metadata
}

func (c *conn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func (c *conn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "nop", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *conn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "nop", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

// Metadata implements metadata.Metadatable interface.
func (c *conn) Metadata() mdata.Metadata {
	return c.md
}
