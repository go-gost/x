package tap

import (
	"errors"
	"net"
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/songgao/water"
)

type conn struct {
	ifce  *water.Interface
	laddr net.Addr
	raddr net.Addr
}

func (c *conn) Read(b []byte) (n int, err error) {
	return c.ifce.Read(b)
}

func (c *conn) Write(b []byte) (n int, err error) {
	return c.ifce.Write(b)
}

func (c *conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Close() (err error) {
	return c.ifce.Close()
}

type metadataConn struct {
	net.Conn
	md mdata.Metadata
}

// GetMetadata implements metadata.Metadatable interface.
func (c *metadataConn) GetMetadata() mdata.Metadata {
	return c.md
}

func withMetadata(md mdata.Metadata, c net.Conn) net.Conn {
	return &metadataConn{
		Conn: c,
		md:   md,
	}
}
