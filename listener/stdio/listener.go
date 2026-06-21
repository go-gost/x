// Package stdio implements a listener that wraps os.Stdin/os.Stdout as a
// net.Listener. It accepts exactly one connection, making it suitable for
// SSH ProxyCommand where the parent process (SSH) pipes the transport byte
// stream through the child process's standard I/O.
//
// Usage: gost -L stdio://example.com:22 -F http://proxy:8080
package stdio

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("stdio", NewListener)
}

type (
	stdioListener struct {
		conn    net.Conn
		done    chan struct{}
		accepted bool
		mu      sync.Mutex
		laddr   net.Addr
		logger  logger.Logger
		md      metadata
		options listener.Options
	}
)

// NewListener creates a stdio listener. The returned listener wraps
// os.Stdin and os.Stdout as a single-use net.Conn.
func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &stdioListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *stdioListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	l.laddr = &stdioAddr{addr: "stdio"}
	l.conn = &stdioConn{}
	l.done = make(chan struct{})

	return
}

// Accept returns the stdio connection on the first call.
// Subsequent calls block until the listener is closed.
func (l *stdioListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()

	<-l.done
	return nil, net.ErrClosed
}

func (l *stdioListener) Addr() net.Addr {
	return l.laddr
}

func (l *stdioListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

// stdioConn implements net.Conn over os.Stdin and os.Stdout.
type stdioConn struct{}

func (c *stdioConn) Read(b []byte) (int, error)  { return os.Stdin.Read(b) }
func (c *stdioConn) Write(b []byte) (int, error) { return os.Stdout.Write(b) }

// Close is a no-op: stdin/stdout are owned by the process and will be
// closed by the parent when the session ends.
func (c *stdioConn) Close() error { return nil }

func (c *stdioConn) LocalAddr() net.Addr  { return &stdioAddr{addr: "stdio"} }
func (c *stdioConn) RemoteAddr() net.Addr { return &stdioAddr{addr: "pipe"} }

// Deadline methods are no-ops: os.Stdin/os.Stdout do not support
// deadline-based I/O.
func (c *stdioConn) SetDeadline(t time.Time) error      { return nil }
func (c *stdioConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stdioConn) SetWriteDeadline(t time.Time) error { return nil }

// stdioAddr is a trivial net.Addr for stdio connections.
type stdioAddr struct {
	addr string
}

func (a *stdioAddr) Network() string { return "tcp" }
func (a *stdioAddr) String() string  { return a.addr }
