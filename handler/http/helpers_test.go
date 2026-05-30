package http

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	cmdata "github.com/go-gost/core/metadata"
	xmetadata "github.com/go-gost/x/metadata"
)

// --- Shared test helpers ---

// testLogger implements logger.Logger for testing. It discards all output.
type testLogger struct{}

func (l *testLogger) WithFields(fields map[string]any) logger.Logger   { return l }
func (l *testLogger) Debug(args ...any)                                 {}
func (l *testLogger) Debugf(format string, args ...any)                 {}
func (l *testLogger) Info(args ...any)                                  {}
func (l *testLogger) Infof(format string, args ...any)                  {}
func (l *testLogger) Warn(args ...any)                                  {}
func (l *testLogger) Warnf(format string, args ...any)                  {}
func (l *testLogger) Error(args ...any)                                 {}
func (l *testLogger) Errorf(format string, args ...any)                 {}
func (l *testLogger) Fatal(args ...any)                                 {}
func (l *testLogger) Fatalf(format string, args ...any)                 {}
func (l *testLogger) GetLevel() logger.LogLevel                         { return logger.InfoLevel }
func (l *testLogger) IsLevelEnabled(level logger.LogLevel) bool         { return false }
func (l *testLogger) Trace(args ...any)                                 {}
func (l *testLogger) Tracef(format string, args ...any)                 {}

// testObserver implements observer.Observer for testing.
type testObserver struct{}

func (o *testObserver) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	return nil
}

// testMD creates metadata from a map for testing.
func testMD(m map[string]any) cmdata.Metadata {
	return xmetadata.NewMetadata(m)
}

// --- Handler factory helpers ---

// newTestHandler creates an httpHandler with default test settings.
// Pass additional options to override defaults.
func newTestHandler(opts ...handler.Option) *httpHandler {
	options := handler.Options{
		Logger: &testLogger{},
	}
	for _, opt := range opts {
		opt(&options)
	}
	h := &httpHandler{
		options: options,
	}
	return h
}

// newInitdHandler creates an httpHandler and calls Init with empty metadata.
func newInitdHandler(opts ...handler.Option) *httpHandler {
	h := newTestHandler(opts...)
	_ = h.Init(testMD(map[string]any{}))
	return h
}

// --- stringConn: in-memory net.Conn for tests ---

// stringConn is an in-memory net.Conn implementation for testing.
// It reads from a prepopulated buffer and captures writes into a separate
// buffer. Useful for testing code that writes HTTP responses without
// needing net.Pipe() + goroutine.
type stringConn struct {
	readBuf   *strings.Reader
	writeBuf  *strings.Builder
	closed    bool
	mu        sync.Mutex
}

func newStringConn(data string) *stringConn {
	return &stringConn{
		readBuf:  strings.NewReader(data),
		writeBuf: &strings.Builder{},
	}
}

func (c *stringConn) Read(b []byte) (int, error)  { return c.readBuf.Read(b) }
func (c *stringConn) Write(b []byte) (int, error)  { return c.writeBuf.Write(b) }
func (c *stringConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *stringConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080} }
func (c *stringConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (c *stringConn) SetDeadline(t time.Time) error      { return nil }
func (c *stringConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stringConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *stringConn) Bytes() []byte                       { return []byte(c.writeBuf.String()) }
func (c *stringConn) String() string                      { return c.writeBuf.String() }
