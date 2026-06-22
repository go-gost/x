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
		conn     net.Conn
		done     chan struct{}
		once     sync.Once
		accepted bool
		mu       sync.Mutex
		laddr    net.Addr
		logger   logger.Logger
		md       metadata
		options  listener.Options
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
	l.done = make(chan struct{})
	l.conn = &stdioConn{l: l}

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
	l.close()
	return nil
}

// close signals listener completion. Idempotent and safe for concurrent use.
func (l *stdioListener) close() {
	l.once.Do(func() { close(l.done) })
}

// stdioConn implements net.Conn over os.Stdin and os.Stdout.
type stdioConn struct {
	l *stdioListener
}

func (c *stdioConn) Read(b []byte) (int, error)  { return os.Stdin.Read(b) }
func (c *stdioConn) Write(b []byte) (int, error) { return os.Stdout.Write(b) }

// Close terminates the process.
//
// A stdio listener serves exactly one connection: the process's own
// stdin/stdout, piped from a parent such as SSH's ProxyCommand. When that
// connection ends the parent has closed the pipe and there is nothing left
// to serve, so the whole process must exit.
//
// Closing the listener alone is not enough: the service's accept loop runs
// in a fire-and-forget goroutine (see x/service.Serve) and the process
// blocks on the go-svc signal wait (see gost/cmd/gost/main.go), so it would
// linger forever after the parent quits. os.Exit is the only reliable way
// to terminate here. The handler's deferred stats/recording/logging already
// ran before this Close (LIFO order), so nothing is lost.
func (c *stdioConn) Close() error {
	c.l.close()
	os.Exit(0)
	return nil
}

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
