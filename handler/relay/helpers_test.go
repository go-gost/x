package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	core_metadata "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/relay"
	xmetadata "github.com/go-gost/x/metadata"
)

// ---------------------------------------------------------------------------
// testLogger — silent logger
// ---------------------------------------------------------------------------

type testLogger struct{}

func (l *testLogger) WithFields(map[string]any) logger.Logger { return l }
func (l *testLogger) IsLevelEnabled(logger.LogLevel) bool     { return false }
func (l *testLogger) GetLevel() logger.LogLevel               { return logger.InfoLevel }
func (l *testLogger) Trace(args ...any)                       {}
func (l *testLogger) Tracef(string, ...any)                   {}
func (l *testLogger) Debug(args ...any)                       {}
func (l *testLogger) Debugf(string, ...any)                   {}
func (l *testLogger) Info(args ...any)                        {}
func (l *testLogger) Infof(string, ...any)                    {}
func (l *testLogger) Warn(args ...any)                        {}
func (l *testLogger) Warnf(string, ...any)                    {}
func (l *testLogger) Error(args ...any)                       {}
func (l *testLogger) Errorf(string, ...any)                   {}
func (l *testLogger) Fatal(args ...any)                       {}
func (l *testLogger) Fatalf(string, ...any)                   {}

// ---------------------------------------------------------------------------
// testMD — wraps a map into metadata.Metadata
// ---------------------------------------------------------------------------

func testMD(m map[string]any) core_metadata.Metadata {
	return xmetadata.NewMetadata(m)
}

// ---------------------------------------------------------------------------
// fakeConn — byte-slice backed net.Conn (reads from buf, collects writes)
// ---------------------------------------------------------------------------

type fakeConn struct {
	net.Conn
	buf      []byte
	offset   int
	writeBuf bytes.Buffer
	closed   bool
	mu       sync.Mutex
	addr     net.Addr
}

func (c *fakeConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.offset >= len(c.buf) {
		return 0, io.EOF
	}
	n := copy(b, c.buf[c.offset:])
	c.offset += n
	return n, nil
}

func (c *fakeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeBuf.Write(b)
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr {
	if c.addr != nil {
		return c.addr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (c *fakeConn) RemoteAddr() net.Addr {
	if c.addr != nil {
		return c.addr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error   { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error  { return nil }

// ---------------------------------------------------------------------------
// pipeConn — bidirectional pipe-based net.Conn using io.Pipe
// ---------------------------------------------------------------------------

type pipeConn struct {
	reader   *io.PipeReader
	writer   *io.PipeWriter
	laddr    net.Addr
	raddr    net.Addr
	closed   bool
	closeMu  sync.Mutex
}

func newPipePair() (*pipeConn, *pipeConn) {
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	a := &pipeConn{reader: pr1, writer: pw2}
	b := &pipeConn{reader: pr2, writer: pw1}
	return a, b
}

func (c *pipeConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *pipeConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.reader.Close()
	c.writer.Close()
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr {
	if c.laddr != nil {
		return c.laddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}
func (c *pipeConn) RemoteAddr() net.Addr {
	if c.raddr != nil {
		return c.raddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------------------
// fakeObserver — channels-based observer with optional error function
// ---------------------------------------------------------------------------

type fakeObserver struct {
	eventsCh chan []observer.Event
	errFunc  func() error // optional; called for each Observe
}

func (o *fakeObserver) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	if o.errFunc != nil {
		if err := o.errFunc(); err != nil {
			return err
		}
	}
	select {
	case o.eventsCh <- events:
	default:
	}
	return nil
}

func (o *fakeObserver) Events() <-chan []observer.Event { return o.eventsCh }

// ---------------------------------------------------------------------------
// mockRouter — implements chain.Router
// ---------------------------------------------------------------------------

type mockRouter struct {
	dialFn func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error)
}

func (r *mockRouter) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	if r.dialFn != nil {
		return r.dialFn(ctx, network, address, opts...)
	}
	return nil, errors.New("mockRouter: no dial function")
}

// Required by chain.Router interface (stubs)
func (r *mockRouter) Options() *chain.RouterOptions { return nil }
func (r *mockRouter) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	return nil, errors.New("mockRouter: Bind not implemented")
}

// ---------------------------------------------------------------------------
// mockHop — implements hop.Hop
// ---------------------------------------------------------------------------

type mockHop struct {
	selectFn func(ctx context.Context) *chain.Node
}

func (h *mockHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if h.selectFn != nil {
		return h.selectFn(ctx)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mockBypass — implements bypass.Bypass
// ---------------------------------------------------------------------------

type mockBypass struct {
	containsFn func(ctx context.Context, network, addr string, opts ...bypass.Option) bool
}

func (b *mockBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if b.containsFn != nil {
		return b.containsFn(ctx, network, addr, opts...)
	}
	return false
}
func (b *mockBypass) IsWhitelist() bool { return false }

// ---------------------------------------------------------------------------
// mockAuther — implements auth.Authenticator
// ---------------------------------------------------------------------------

type mockAuther struct {
	authenticateFn func(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool)
}

func (a *mockAuther) Authenticate(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
	if a.authenticateFn != nil {
		return a.authenticateFn(ctx, user, pass, opts...)
	}
	return "", false
}

// ---------------------------------------------------------------------------
// mockRateLimiter — implements rate.Limiter (single rate limiter)
// ---------------------------------------------------------------------------

type mockRateLimiter struct {
	allowFn func(n int) bool
	waitFn  func(ctx context.Context) error
}

func (l *mockRateLimiter) Allow(n int) bool {
	if l.allowFn != nil {
		return l.allowFn(n)
	}
	return true
}
func (l *mockRateLimiter) Limit() float64 { return 1 }
func (l *mockRateLimiter) Wait(ctx context.Context) error {
	if l.waitFn != nil {
		return l.waitFn(ctx)
	}
	return nil
}

// mockRateLimiterContainer — implements rate.RateLimiter (container by key)
type mockRateLimiterContainer struct {
	limiterFn func(key string) rate.Limiter
}

func (c *mockRateLimiterContainer) Limiter(key string) rate.Limiter {
	if c.limiterFn != nil {
		return c.limiterFn(key)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mockTrafficLimiter — implements traffic.TrafficLimiter
// ---------------------------------------------------------------------------

type mockTrafficLimiter struct{}

func (l *mockTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return nil
}
func (l *mockTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return nil
}

// ---------------------------------------------------------------------------
// buildRelayRequest helpers — serialize relay requests for fakeConn.buf
// ---------------------------------------------------------------------------

func buildRelayConnectRequest(t testingT, address, network string) []byte {
	t.Helper()
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}

	af := &relay.AddrFeature{}
	if address != "" {
		if err := af.ParseFrom(address); err != nil {
			t.Fatal(err)
		}
	}
	req.Features = append(req.Features, af)

	if network != "" && network != "tcp" {
		req.Features = append(req.Features, &relay.NetworkFeature{
			Network: toRelayNetworkID(network),
		})
	}

	var buf bytes.Buffer
	if _, err := req.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildRelayBindRequest(t testingT, address, network string) []byte {
	t.Helper()
	cmd := relay.CmdBind
	if network == "udp" || network == "udp4" || network == "udp6" {
		cmd |= relay.FUDP
	}
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     cmd,
	}

	af := &relay.AddrFeature{}
	if address != "" {
		if err := af.ParseFrom(address); err != nil {
			t.Fatal(err)
		}
	}
	req.Features = append(req.Features, af)

	if network != "" && network != "tcp" {
		req.Features = append(req.Features, &relay.NetworkFeature{
			Network: toRelayNetworkID(network),
		})
	}

	var buf bytes.Buffer
	if _, err := req.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func toRelayNetworkID(n string) relay.NetworkID {
	switch n {
	case "udp", "udp4", "udp6":
		return relay.NetworkUDP
	case "unix":
		return relay.NetworkUnix
	case "serial":
		return relay.NetworkSerial
	default:
		return relay.NetworkTCP
	}
}

// testingT is a subset of testing.T for use by helper functions.
type testingT interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// ---------------------------------------------------------------------------
// makeTestNode — creates a minimal *hop.Node for mockHop returns
// ---------------------------------------------------------------------------

func makeTestNode(addr string) *chain.Node {
	return chain.NewNode("test", addr)
}

// ---------------------------------------------------------------------------
// readRelayResponse — deserializes a relay.Response from bytes
// ---------------------------------------------------------------------------

func readRelayResponse(t testingT, data []byte) *relay.Response {
	t.Helper()
	resp := &relay.Response{}
	if _, err := resp.ReadFrom(bytes.NewReader(data)); err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	return resp
}