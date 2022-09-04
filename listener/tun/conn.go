package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	mdata "github.com/go-gost/core/metadata"
)

type conn struct {
	ifce   io.ReadWriteCloser
	laddr  net.Addr
	raddr  net.Addr
	cancel context.CancelFunc
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
	return &net.OpError{Op: "set", Net: "tun", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tun", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tun", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Close() (err error) {
	if c.cancel != nil {
		c.cancel()
	}
	return c.ifce.Close()
}

type metadataConn struct {
	net.Conn
	md mdata.Metadata
}

// Metadata implements metadata.Metadatable interface.
func (c *metadataConn) Metadata() mdata.Metadata {
	return c.md
}

func withMetadata(md mdata.Metadata, c net.Conn) net.Conn {
	return &metadataConn{
		Conn: c,
		md:   md,
	}
}
