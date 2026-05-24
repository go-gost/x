package direct

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/go-gost/core/common/net"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	mdx "github.com/go-gost/x/metadata"
)

type testDialer struct {
	conn net.Conn
	err  error
}

func (d *testDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.conn, d.err
}

func TestNewConnector(t *testing.T) {
	c := NewConnector()
	if c == nil {
		t.Fatal("NewConnector returned nil")
	}
}

func TestNewConnectorWithOptions(t *testing.T) {
	c := NewConnector(connector.LoggerOption(logger.Default()))
	if c == nil {
		t.Fatal("NewConnector returned nil")
	}

	if err := c.Init(mdx.NewMetadata(nil)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestInit(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		action   string
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			action:   "",
		},
		{
			name:     "empty metadata",
			metadata: map[string]any{},
			action:   "",
		},
		{
			name:     "action reject",
			metadata: map[string]any{"action": "reject"},
			action:   "reject",
		},
		{
			name:     "action reject with capitals",
			metadata: map[string]any{"action": "REJECT"},
			action:   "reject",
		},
		{
			name:     "unknown action",
			metadata: map[string]any{"action": "unknown"},
			action:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConnector()
			if err := c.Init(mdx.NewMetadata(tt.metadata)); err != nil {
				t.Fatalf("Init failed: %v", err)
			}

			dc, ok := c.(*directConnector)
			if !ok {
				t.Fatal("not a *directConnector")
			}
			if dc.md.action != tt.action {
				t.Errorf("expected action %q, got %q", tt.action, dc.md.action)
			}
		})
	}
}

func TestConnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	c := NewConnector()
	c.Init(mdx.NewMetadata(nil))

	conn, err := c.Connect(context.Background(), nil, "tcp", l.Addr().String(),
		connector.DialerConnectOption(&testDialer{conn: client}),
	)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if conn == nil {
		t.Fatal("Connect returned nil conn")
	}
	conn.Close()
	<-done
}

func TestConnectRejectAction(t *testing.T) {
	c := NewConnector()
	c.Init(mdx.NewMetadata(map[string]any{"action": "reject"}))

	conn, err := c.Connect(context.Background(), nil, "tcp", "127.0.0.1:12345",
		connector.DialerConnectOption(&testDialer{}),
	)
	if err != nil {
		t.Fatalf("Connect with reject action failed: %v", err)
	}
	if conn == nil {
		t.Fatal("Connect with reject action returned nil conn")
	}

	// Verify dead conn behavior
	b := make([]byte, 1)
	_, err = conn.Read(b)
	if err != io.EOF {
		t.Errorf("expected io.EOF on Read from reject conn, got %v", err)
	}

	_, err = conn.Write(b)
	if err != io.ErrClosedPipe {
		t.Errorf("expected io.ErrClosedPipe on Write to reject conn, got %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Errorf("expected nil Close on reject conn, got %v", err)
	}
}

func TestConnectNilDialer(t *testing.T) {
	c := NewConnector()
	c.Init(mdx.NewMetadata(nil))

	_, err := c.Connect(context.Background(), nil, "tcp", "127.0.0.1:12345")
	if err == nil {
		t.Fatal("expected error for nil dialer, got nil")
	}
	if err.Error() != "direct: missing dialer in connect options" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConnectNilLogger(t *testing.T) {
	// No LoggerOption set — should not panic
	c := NewConnector()
	c.Init(mdx.NewMetadata(nil))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := l.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	conn, err := c.Connect(context.Background(), nil, "tcp", l.Addr().String(),
		connector.DialerConnectOption(&testDialer{conn: client}),
	)
	if err != nil {
		t.Fatalf("Connect with nil logger failed: %v", err)
	}
	conn.Close()
	<-done
}

func TestConnectDialError(t *testing.T) {
	c := NewConnector()
	c.Init(mdx.NewMetadata(nil))

	dialErr := io.ErrUnexpectedEOF
	_, err := c.Connect(context.Background(), nil, "tcp", "127.0.0.1:12345",
		connector.DialerConnectOption(&testDialer{err: dialErr}),
	)
	if err != dialErr {
		t.Errorf("expected %v, got %v", dialErr, err)
	}
}

func TestRejectConn(t *testing.T) {
	c := &conn{}

	// Read returns io.EOF
	b := make([]byte, 10)
	n, err := c.Read(b)
	if n != 0 {
		t.Errorf("Read returned %d bytes, expected 0", n)
	}
	if err != io.EOF {
		t.Errorf("Read returned %v, expected io.EOF", err)
	}

	// Write returns io.ErrClosedPipe
	n, err = c.Write(b)
	if n != 0 {
		t.Errorf("Write returned %d bytes, expected 0", n)
	}
	if err != io.ErrClosedPipe {
		t.Errorf("Write returned %v, expected io.ErrClosedPipe", err)
	}

	// Close returns nil
	if err := c.Close(); err != nil {
		t.Errorf("Close returned %v, expected nil", err)
	}

	// LocalAddr returns non-nil
	if addr := c.LocalAddr(); addr == nil {
		t.Error("LocalAddr returned nil")
	}

	// RemoteAddr returns non-nil
	if addr := c.RemoteAddr(); addr == nil {
		t.Error("RemoteAddr returned nil")
	}

	// Deadline methods return nil
	if err := c.SetDeadline(time.Now()); err != nil {
		t.Errorf("SetDeadline returned %v, expected nil", err)
	}
	if err := c.SetReadDeadline(time.Now()); err != nil {
		t.Errorf("SetReadDeadline returned %v, expected nil", err)
	}
	if err := c.SetWriteDeadline(time.Now()); err != nil {
		t.Errorf("SetWriteDeadline returned %v, expected nil", err)
	}
}

// Ensure xnet.Dialer interface matches at compile time
var _ xnet.Dialer = (*testDialer)(nil)
