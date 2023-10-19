package dtls

import (
	"bytes"
	"net"

	"github.com/go-gost/core/common/bufpool"
)

type dtlsConn struct {
	net.Conn
	rbuf       bytes.Buffer
	bufferSize int
}

func Conn(c net.Conn, bufferSize int) net.Conn {
	return &dtlsConn{
		Conn:       c,
		bufferSize: bufferSize,
	}
}

func (c *dtlsConn) Read(p []byte) (n int, err error) {
	/*
		defer func() {
			logger.Default().Debugf("dtls: read data %d/%d, %v", n, len(p), err)
		}()
	*/

	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(p)
	}

	bufferSize := c.bufferSize
	if len(p) >= bufferSize {
		return c.Conn.Read(p)
	}

	buf := bufpool.Get(bufferSize)
	defer bufpool.Put(buf)

	nn, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}

	n = copy(p, buf[:nn])
	c.rbuf.Write(buf[n:nn])

	return
}

func (c *dtlsConn) Write(p []byte) (n int, err error) {
	/*
		defer func() {
			logger.Default().Debugf("dtls: write data %d, %v", n, err)
		}()
	*/

	for len(p) > 0 {
		nn := c.bufferSize
		if nn > len(p) {
			nn = len(p)
		}
		nn, err = c.Conn.Write(p[:nn])
		n += nn
		if err != nil {
			return
		}
		p = p[nn:]
	}
	return
}
