package tunnel

import (
	"bytes"
	"net"
)

type tcpConn struct {
	net.Conn
	wbuf bytes.Buffer
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append the data to the cached header
		_, err = c.wbuf.WriteTo(c.Conn)
		return
	}
	_, err = c.Conn.Write(b)
	return
}
