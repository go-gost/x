package router

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	core_metadata "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	xmetadata "github.com/go-gost/x/metadata"
)

// ---------------------------------------------------------------------------
// testLogger
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
// testMD
// ---------------------------------------------------------------------------

func testMD(m map[string]any) core_metadata.Metadata {
	return xmetadata.NewMetadata(m)
}

// ---------------------------------------------------------------------------
// fakeConn — bytes.Buffer-backed net.Conn
// ---------------------------------------------------------------------------

type fakeConn struct {
	net.Conn
	buf      []byte
	offset   int
	writeBuf bytes.Buffer
	closed   bool
	mu       sync.Mutex
	laddr    net.Addr
	raddr    net.Addr
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
	if c.laddr != nil {
		return c.laddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (c *fakeConn) RemoteAddr() net.Addr {
	if c.raddr != nil {
		return c.raddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error   { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error  { return nil }

// ---------------------------------------------------------------------------
// pipeConn — bidirectional pipe-based net.Conn
// ---------------------------------------------------------------------------

type pipeConn struct {
	reader  *io.PipeReader
	writer  *io.PipeWriter
	laddr   net.Addr
	raddr   net.Addr
	closed  bool
	closeMu sync.Mutex
}

func newPipePair() (*pipeConn, *pipeConn) {
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	a := &pipeConn{reader: pr1, writer: pw2}
	b := &pipeConn{reader: pr2, writer: pw1}
	a.laddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	a.raddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	b.laddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	b.raddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
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
// fakePacketConn — channel-backed net.PacketConn
// ---------------------------------------------------------------------------

type fakePacketConn struct {
	dataCh  chan []byte
	addrCh  chan net.Addr
	closed  bool
	closeMu sync.Mutex
	laddr   net.Addr
}

func newFakePacketConn(laddr net.Addr) *fakePacketConn {
	return &fakePacketConn{
		dataCh: make(chan []byte, 64),
		addrCh: make(chan net.Addr, 64),
		laddr:  laddr,
	}
}

func (c *fakePacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data, ok := <-c.dataCh
	if !ok {
		return 0, nil, io.EOF
	}
	n = copy(b, data)
	addr = <-c.addrCh
	return
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	data := make([]byte, len(b))
	copy(data, b)
	c.dataCh <- data
	c.addrCh <- addr
	return len(b), nil
}

func (c *fakePacketConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.dataCh)
		close(c.addrCh)
	}
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return c.laddr }

func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------------------
// fakeObserver — channel-based observer
// ---------------------------------------------------------------------------

type fakeObserver struct {
	eventsCh chan []observer.Event
	errFunc  func() error
}

func newFakeObserver(buffer int) *fakeObserver {
	return &fakeObserver{
		eventsCh: make(chan []observer.Event, buffer),
	}
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
// mockAuther
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
// mockRateLimiter + mockRateLimiterContainer
// ---------------------------------------------------------------------------

type mockRateLimiter struct {
	allowFn func(n int) bool
}

func (l *mockRateLimiter) Allow(n int) bool {
	if l.allowFn != nil {
		return l.allowFn(n)
	}
	return true
}
func (l *mockRateLimiter) Limit() float64                        { return 1 }
func (l *mockRateLimiter) Wait(ctx context.Context) error        { return nil }

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
// mockTrafficLimiter
// ---------------------------------------------------------------------------

type mockTrafficLimiter struct{}

func (l *mockTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return nil
}
func (l *mockTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return nil
}

// ---------------------------------------------------------------------------
// mockRouter — implements core/router.Router
// ---------------------------------------------------------------------------

type mockRouter struct {
	getRouteFn func(ctx context.Context, dst string, opts ...router.Option) *router.Route
}

func (r *mockRouter) GetRoute(ctx context.Context, dst string, opts ...router.Option) *router.Route {
	if r.getRouteFn != nil {
		return r.getRouteFn(ctx, dst, opts...)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mockSD
// ---------------------------------------------------------------------------

type mockSD struct {
	getFn         func(ctx context.Context, name string) ([]*sd.Service, error)
	registerFn    func(ctx context.Context, svc *sd.Service, opts ...sd.Option) error
	deregisterFn  func(ctx context.Context, svc *sd.Service) error
	renewFn       func(ctx context.Context, svc *sd.Service) error
}

func (s *mockSD) Get(ctx context.Context, name string) ([]*sd.Service, error) {
	if s.getFn != nil {
		return s.getFn(ctx, name)
	}
	return nil, nil
}
func (s *mockSD) Register(ctx context.Context, svc *sd.Service, opts ...sd.Option) error {
	if s.registerFn != nil {
		return s.registerFn(ctx, svc, opts...)
	}
	return nil
}
func (s *mockSD) Deregister(ctx context.Context, svc *sd.Service) error {
	if s.deregisterFn != nil {
		return s.deregisterFn(ctx, svc)
	}
	return nil
}
func (s *mockSD) Renew(ctx context.Context, svc *sd.Service) error {
	if s.renewFn != nil {
		return s.renewFn(ctx, svc)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mockIngress
// ---------------------------------------------------------------------------

type mockIngress struct {
	setRuleFn func(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool
	getRuleFn func(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule
}

func (ing *mockIngress) SetRule(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool {
	if ing.setRuleFn != nil {
		return ing.setRuleFn(ctx, rule, opts...)
	}
	return false
}

func (ing *mockIngress) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
	if ing.getRuleFn != nil {
		return ing.getRuleFn(ctx, host, opts...)
	}
	return nil
}

// ---------------------------------------------------------------------------
// buildRelayAssociateRequest — serializes a relay association request to bytes
// ---------------------------------------------------------------------------

func buildRelayAssociateRequest(t testingT, address string, routerID relay.TunnelID, network string) []byte {
	t.Helper()
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
	}

	if address != "" {
		af := &relay.AddrFeature{}
		if err := af.ParseFrom(address); err != nil {
			t.Fatal(err)
		}
		req.Features = append(req.Features, af)
	}

	req.Features = append(req.Features, &relay.TunnelFeature{ID: routerID})

	networkID := relay.NetworkIP
	switch network {
	case "ip", "ip4", "ip6":
		networkID = relay.NetworkIP
	}
	req.Features = append(req.Features, &relay.NetworkFeature{Network: networkID})

	var buf bytes.Buffer
	if _, err := req.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// readRelayResponse — deserializes relay.Response from bytes
// ---------------------------------------------------------------------------

func readRelayResponse(t testingT, data []byte) *relay.Response {
	t.Helper()
	resp := &relay.Response{}
	if _, err := resp.ReadFrom(bytes.NewReader(data)); err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// testingT interface
// ---------------------------------------------------------------------------

type testingT interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// ---------------------------------------------------------------------------
// IP packet builders for handlePacket tests
// ---------------------------------------------------------------------------

func buildIPv4Packet(srcIP, dstIP string, payload []byte) []byte {
	const headerLen = 20
	totalLen := headerLen + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], net.ParseIP(srcIP).To4())
	copy(pkt[16:20], net.ParseIP(dstIP).To4())

	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	pkt[10] = byte(^sum >> 8)
	pkt[11] = byte(^sum & 0xFF)

	copy(pkt[headerLen:], payload)
	return pkt
}

func buildIPv6Packet(srcIP, dstIP string, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60
	pkt[4] = byte(len(payload) >> 8)
	pkt[5] = byte(len(payload))
	pkt[6] = 17
	pkt[7] = 64
	copy(pkt[8:24], net.ParseIP(srcIP).To16())
	copy(pkt[24:40], net.ParseIP(dstIP).To16())
	copy(pkt[40:], payload)
	return pkt
}