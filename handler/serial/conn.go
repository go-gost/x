package serial

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"time"

	"github.com/go-gost/core/recorder"
)

type recorderConn struct {
	net.Conn
	recorder recorder.Recorder
}

func (c *recorderConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)

	if n > 0 && c.recorder != nil {
		var buf bytes.Buffer
		buf.WriteByte('>')
		buf.WriteString(time.Now().Format("2006-01-02 15:04:05.000"))
		buf.WriteByte('\n')
		buf.WriteString(hex.Dump(b[:n]))
		c.recorder.Record(context.Background(), buf.Bytes())
	}

	return
}

func (c *recorderConn) Write(b []byte) (int, error) {
	if c.recorder != nil {
		var buf bytes.Buffer
		buf.WriteByte('<')
		buf.WriteString(time.Now().Format("2006-01-02 15:04:05.000"))
		buf.WriteByte('\n')
		buf.WriteString(hex.Dump(b))
		c.recorder.Record(context.Background(), buf.Bytes())
	}
	return c.Conn.Write(b)

}
