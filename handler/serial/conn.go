package serial

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"time"

	"github.com/go-gost/core/recorder"
)

// recorderConn wraps a net.Conn to record raw traffic flowing through it.
// Each successful Read or Write that transfers data is logged via the
// configured Recorder, optionally annotated with direction markers,
// timestamps, and hex dumps.
//
// The direction convention is:
//   - Read:  '>' (data entering GOST from the serial port / client side)
//   - Write: '<' (data leaving GOST toward the serial port / client side)
//
// This provides a per-packet-level traffic log, as opposed to the
// aggregate stats approach used by handlers like redirect/tcp (which
// accumulate total byte counts and record once at the end).
type recorderConn struct {
	net.Conn
	recorder recorder.RecorderObject
}

// Read reads from the underlying connection and records the received data.
// Recording happens only when bytes were actually read (n > 0) AND a
// Recorder is configured. If Read returns an error alongside data
// (e.g. io.EOF after the last chunk), the data is still recorded —
// partial reads before an error are meaningful traffic.
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

// Write writes to the underlying connection and records the sent data.
// Recording follows the same rules as Read: only when n > 0 and a
// Recorder is configured. The direction marker is '<' to indicate
// outbound traffic (data leaving GOST toward the target).
func (c *recorderConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)

	if n > 0 && c.recorder.Recorder != nil {
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
			buf.WriteString(hex.Dump(b[:n]))
		} else {
			buf.Write(b[:n])
		}
		c.recorder.Recorder.Record(context.Background(), buf.Bytes())
	}

	return
}
