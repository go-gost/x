package local

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// mockRouter implements chain.Router.
type mockRouter struct {
	opts   *chain.RouterOptions
	dialFn func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockRouter) Options() *chain.RouterOptions { return m.opts }
func (m *mockRouter) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	if m.dialFn != nil {
		return m.dialFn(ctx, network, address)
	}
	return nil, nil
}
func (m *mockRouter) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	return nil, nil
}

// mockHop implements hop.Hop.
type mockHop struct {
	selectFn func(ctx context.Context, opts ...hop.SelectOption) *chain.Node
}

func (m *mockHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if m.selectFn != nil {
		return m.selectFn(ctx, opts...)
	}
	return nil
}

type stubRateLimiter struct {
	limiterFn func(key string) rate.Limiter
}

func (m *stubRateLimiter) Limiter(key string) rate.Limiter {
	if m.limiterFn != nil {
		return m.limiterFn(key)
	}
	return nil
}

type stubLimiter struct {
	allowFn func(n int) bool
}

func (m *stubLimiter) Allow(n int) bool {
	if m.allowFn != nil {
		return m.allowFn(n)
	}
	return true
}

func (m *stubLimiter) Limit() float64 { return 0 }

// mockRecorder implements recorder.Recorder.
type mockRecorder struct{}

func (m *mockRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	return nil
}
func (m *mockRecorder) Close() error { return nil }

type errorRecorder struct{}

func (e *errorRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	return errors.New("record error")
}
func (e *errorRecorder) Close() error { return nil }

// stringConn is a net.Conn backed by bytes.Buffer for testing.
type stringConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	local    net.Addr
	remote   net.Addr
	closed   bool
	mu       sync.Mutex
}

func newStringConn(data []byte) *stringConn {
	return &stringConn{
		readBuf:  bytes.NewBuffer(data),
		writeBuf: new(bytes.Buffer),
		local:    &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		remote:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345},
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
func (c *stringConn) LocalAddr() net.Addr                { return c.local }
func (c *stringConn) RemoteAddr() net.Addr               { return c.remote }
func (c *stringConn) SetDeadline(t time.Time) error      { return nil }
func (c *stringConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stringConn) SetWriteDeadline(t time.Time) error { return nil }

type packetConn struct {
	*stringConn
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error)  { return 0, nil, nil }
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nopLog() logger.Logger { return xlogger.Nop() }

func newTestHandler(opts ...handler.Option) *forwardHandler {
	options := handler.Options{
		Logger: nopLog(),
		Router: &mockRouter{opts: &chain.RouterOptions{}},
	}
	for _, opt := range opts {
		opt(&options)
	}
	return &forwardHandler{
		options: options,
		sniffer: &SnifferBuilder{},
	}
}

func newInitdHandler(opts ...handler.Option) *forwardHandler {
	h := newTestHandler(opts...)
	_ = h.Init(xmd.NewMetadata(nil))
	return h
}

// withRateLimiter is a helper to set the RateLimiter option.
func withRateLimiter(rl rate.RateLimiter) handler.Option {
	return func(o *handler.Options) {
		o.RateLimiter = rl
	}
}

// withRouter is a helper to set the Router option.
func withRouter(r chain.Router) handler.Option {
	return func(o *handler.Options) {
		o.Router = r
	}
}

// withRecorder is a helper to append a RecorderObject to the Recorders slice.
func withRecorder(ro recorder.RecorderObject) handler.Option {
	return func(o *handler.Options) {
		o.Recorders = append(o.Recorders, ro)
	}
}

// ---------------------------------------------------------------------------
// Test certificate helpers
// ---------------------------------------------------------------------------

func generateTestCertKey(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

func generateTestCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	cert, key := generateTestCertKey(t)
	certPEM = pemEncode("CERTIFICATE", cert.Raw)
	keyBytes := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
	keyPEM = pemEncode("RSA PRIVATE KEY", keyBytes)
	return
}

func pemEncode(blockType string, der []byte) []byte {
	block := &pem.Block{Type: blockType, Bytes: der}
	return pem.EncodeToMemory(block)
}

func writeTempFile(t *testing.T, pattern string, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
