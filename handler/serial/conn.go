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
	recorder recorder.RecorderObject
}

func (c *recorderConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)

	if n > 0 && c.recorder.Recorder != nil {
		var buf bytes.Buffer
		if c.recorder.Options != nil && c.recorder.Options.Direction {
			buf.WriteByte('>')
		}
		if c.recorder.Options != nil && c.recorder.Options.TimestampFormat != "" {
			buf.WriteString(time.Now().Format(c.recorder.Options.TimestampFormat))
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		if c.recorder.Options != nil && c.recorder.Options.Hexdump {
			buf.WriteString(hex.Dump(b[:n]))
		} else {
			buf.Write(b[:n])
		}
		c.recorder.Recorder.Record(context.Background(), buf.Bytes())
	}

	return
}

func (c *recorderConn) Write(b []byte) (int, error) {
	if c.recorder.Recorder != nil {
		var buf bytes.Buffer
		if c.recorder.Options != nil && c.recorder.Options.Direction {
			buf.WriteByte('<')
		}
		if c.recorder.Options != nil && c.recorder.Options.TimestampFormat != "" {
			buf.WriteString(time.Now().Format(c.recorder.Options.TimestampFormat))
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		if c.recorder.Options != nil && c.recorder.Options.Hexdump {
			buf.WriteString(hex.Dump(b))
		} else {
			buf.Write(b)
		}
		c.recorder.Recorder.Record(context.Background(), buf.Bytes())
	}
	return c.Conn.Write(b)
}
