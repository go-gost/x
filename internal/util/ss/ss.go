package ss

import (
	"bytes"
	"net"

	xio "github.com/go-gost/x/internal/io"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

func ShadowCipher(method, password string, key string) (core.Cipher, error) {
	if method == "" || password == "" {
		return nil, nil
	}
	return core.PickCipher(method, []byte(key), password)
}

// Due to in/out byte length is inconsistent of the shadowsocks.Conn.Write,
// we wrap around it to make io.Copy happy.
type shadowConn struct {
	net.Conn
	wbuf bytes.Buffer
}

func ShadowConn(conn net.Conn, header []byte) net.Conn {
	c := &shadowConn{
		Conn: conn,
	}
	c.wbuf.Write(header)
	return c
}

func (c *shadowConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append the data to the cached header
		_, err = c.Conn.Write(c.wbuf.Bytes())
		c.wbuf.Reset()
		return
	}
	_, err = c.Conn.Write(b)
	return
}

func (c *shadowConn) CloseRead() error {
	if sc, ok := c.Conn.(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *shadowConn) CloseWrite() error {
	if sc, ok := c.Conn.(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}
