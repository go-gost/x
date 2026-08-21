package ss

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/go-gost/x/internal/util/ss/none"
	xlogger "github.com/go-gost/x/logger"
	mdx "github.com/go-gost/x/metadata"
)

// captureConn records everything written to it, so a test can inspect the
// bytes a connector actually puts on the wire.
type captureConn struct {
	buf bytes.Buffer
}

func (c *captureConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(b []byte) (int, error)        { return c.buf.Write(b) }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error        { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error    { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error   { return nil }

// TestConnectTargetNotOverwrittenByPool is a regression test for
// https://github.com/go-gost/gost/issues/896: the connector previously passed
// a slice aliasing the bufpool buffer to WrapConn, and the buffer was returned
// to the pool before the wrapped conn lazily wrote the target on first I/O. A
// second Connect could then overwrite the bytes and the first conn would send
// the second conn's target. The none cipher keeps the wire plaintext so the
// written target is directly assertable.
func TestConnectTargetNotOverwrittenByPool(t *testing.T) {
	c := NewConnector(
		connector.AuthOption(url.UserPassword("none", "x")),
		connector.LoggerOption(xlogger.NewLogger()),
	)
	if err := c.Init(mdx.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	ctx := context.Background()
	cap1 := &captureConn{}
	conn1, err := c.Connect(ctx, cap1, "tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatalf("first Connect: %v", err)
	}

	// Second Connect reuses the same 512-byte bufpool buffer that conn1's
	// target used to alias (single pool tier, same goroutine).
	if _, err := c.Connect(ctx, &captureConn{}, "tcp", "5.6.7.8:443"); err != nil {
		t.Fatalf("second Connect: %v", err)
	}

	if _, err := conn1.Write([]byte("X")); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	// initWriter frames the target as [salt][2-byte length][addr].
	data := cap1.buf.Bytes()
	payload := data[none.Cipher.SaltSize():]
	if len(payload) < 2 {
		t.Fatalf("captured payload too short: %d bytes: %x", len(payload), data)
	}
	n := int(payload[0])<<8 | int(payload[1])
	if len(payload) < 2+n {
		t.Fatalf("captured payload too short: len=%d, need %d: %x", len(payload), 2+n, data)
	}
	addr := socks.SplitAddr(payload[2 : 2+n])
	if got, want := addr.String(), "1.2.3.4:80"; got != want {
		t.Fatalf("first conn wrote target %q, want %q (captured %x)", got, want, data)
	}
}
