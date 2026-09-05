package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/p2p/proto"
	"github.com/go-gost/x/dialer/tcp"
	xlogger "github.com/go-gost/x/logger"
	xp2p "github.com/go-gost/x/p2p"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMain installs the global default logger: components built with
// logger.Default() panic on nil in test binaries (the CLI bootstrap sets it
// in production).
func TestMain(m *testing.M) {
	logger.SetDefault(xlogger.Nop())
	os.Exit(m.Run())
}

// fakeServer implements the P2P control contract: OpenTunnel validates the
// peer, creates a local listener bridged to it, CloseTunnel tears it down.
// Flags flip the failure paths: deadEndpoint returns an endpoint whose port
// is already closed, bizFail answers ok:false body with a gRPC status OK.
type fakeServer struct {
	proto.UnimplementedP2PServer
	mu           sync.Mutex
	seq          atomic.Int64
	tunnels      map[string]*fakeTunnel
	deadEndpoint bool
	bizFail      bool
}

type fakeTunnel struct {
	target string
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
}

func (s *fakeServer) OpenTunnel(ctx context.Context, req *proto.OpenTunnelRequest) (*proto.OpenTunnelReply, error) {
	host, port, err := net.SplitHostPort(req.Peer)
	if err != nil || host == "" || port == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q", req.Peer)
	}
	if s.bizFail {
		return &proto.OpenTunnelReply{Ok: false, Error: "biz boom"}, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return &proto.OpenTunnelReply{Ok: false, Error: err.Error()}, nil
	}
	endpoint := ln.Addr().String()
	if s.deadEndpoint {
		ln.Close() // endpoint is dead; the tunnel is still tracked for cleanup
	}
	t := &fakeTunnel{target: req.Peer, ln: ln, conns: make(map[net.Conn]struct{})}
	id := fmt.Sprintf("t-%d", s.seq.Add(1))
	s.mu.Lock()
	s.tunnels[id] = t
	s.mu.Unlock()
	if !s.deadEndpoint {
		go t.serve()
	}
	return &proto.OpenTunnelReply{Ok: true, Id: id, Endpoint: endpoint}, nil
}

func (s *fakeServer) CloseTunnel(ctx context.Context, req *proto.CloseTunnelRequest) (*proto.CloseTunnelReply, error) {
	s.mu.Lock()
	t, ok := s.tunnels[req.Id]
	delete(s.tunnels, req.Id)
	s.mu.Unlock()
	if ok {
		t.close()
	}
	return &proto.CloseTunnelReply{Ok: true}, nil
}

func (s *fakeServer) Status(ctx context.Context, req *proto.StatusRequest) (*proto.StatusReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &proto.StatusReply{Tunnels: int32(len(s.tunnels))}, nil
}

func (s *fakeServer) tunnelCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tunnels)
}

func (t *fakeTunnel) serve() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		t.mu.Lock()
		t.conns[conn] = struct{}{}
		t.mu.Unlock()
		go t.bridge(conn)
	}
}

func (t *fakeTunnel) bridge(conn net.Conn) {
	defer func() {
		t.mu.Lock()
		delete(t.conns, conn)
		t.mu.Unlock()
	}()
	up, err := net.DialTimeout("tcp", t.target, 5*time.Second)
	if err != nil {
		conn.Close()
		return
	}
	defer func() {
		up.Close()
		conn.Close()
	}()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, up)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (t *fakeTunnel) close() {
	t.ln.Close()
	t.mu.Lock()
	defer t.mu.Unlock()
	for conn := range t.conns {
		conn.Close()
	}
}

// startFake runs the fake control server and returns its address; the
// server is stopped at test cleanup.
func startFake(t *testing.T, s *fakeServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	proto.RegisterP2PServer(gs, s)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)
	return ln.Addr().String()
}

// startEcho runs a loopback echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func echoOnce(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func newTestDialer(t *testing.T, s *fakeServer) (dialer.Dialer, xp2p.TunnelProvider) {
	t.Helper()
	provider := NewGRPCPlugin("t", startFake(t, s))
	inner := tcp.NewDialer(dialer.LoggerOption(logger.Default()))
	return xp2p.NewTunnelDialer(inner, provider), provider
}

func TestDialRoundTrip(t *testing.T) {
	s := &fakeServer{tunnels: make(map[string]*fakeTunnel)}
	d, _ := newTestDialer(t, s)
	target := startEcho(t)

	conn, err := d.Dial(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.tunnelCount(); n != 1 {
		t.Fatalf("tunnel count = %d, want 1", n)
	}
	echoOnce(t, conn)

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count after close = %d, want 0", n)
	}
	// second Close must be a no-op (sync.Once), not an error or panic
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count after double close = %d, want 0", n)
	}
}

func TestPluginDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	provider := NewGRPCPlugin("t", dead)
	inner := tcp.NewDialer(dialer.LoggerOption(logger.Default()))
	d := xp2p.NewTunnelDialer(inner, provider)
	if _, err := d.Dial(context.Background(), "127.0.0.1:9999"); err == nil {
		t.Fatal("Dial succeeded, want fail-closed error")
	}
}

func TestLocalEndpointDead(t *testing.T) {
	s := &fakeServer{tunnels: make(map[string]*fakeTunnel), deadEndpoint: true}
	d, _ := newTestDialer(t, s)

	if _, err := d.Dial(context.Background(), "127.0.0.1:9999"); err == nil {
		t.Fatal("Dial succeeded, want error on dead endpoint")
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count after failed dial = %d, want 0 (cleanup ran)", n)
	}
}

func TestDialConcurrent(t *testing.T) {
	s := &fakeServer{tunnels: make(map[string]*fakeTunnel)}
	d, _ := newTestDialer(t, s)
	target := startEcho(t)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			conn, err := d.Dial(context.Background(), target)
			if err != nil {
				t.Error(err)
				return
			}
			echoOnce(t, conn)
			conn.Close()
		})
	}
	wg.Wait()
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count after concurrent dials = %d, want 0", n)
	}
}

func TestOpenTunnelInvalidPeer(t *testing.T) {
	s := &fakeServer{tunnels: make(map[string]*fakeTunnel)}
	d, _ := newTestDialer(t, s)

	if _, err := d.Dial(context.Background(), "foo"); err == nil {
		t.Fatal("Dial succeeded, want invalid-peer error")
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

func TestOpenTunnelBizFail(t *testing.T) {
	s := &fakeServer{tunnels: make(map[string]*fakeTunnel), bizFail: true}
	d, _ := newTestDialer(t, s)

	_, err := d.Dial(context.Background(), "127.0.0.1:9999")
	if err == nil {
		t.Fatal("Dial succeeded, want business-failure error")
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

// handshakeDialer wraps an inner dialer and records the handshake address.
type handshakeDialer struct {
	dialer.Dialer
	addr string
}

func (d *handshakeDialer) Handshake(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
	var options dialer.HandshakeOptions
	for _, opt := range opts {
		opt(&options)
	}
	d.addr = options.Addr
	return conn, nil
}

func TestHandshakeForward(t *testing.T) {
	s := &fakeServer{tunnels: make(map[string]*fakeTunnel)}
	provider := NewGRPCPlugin("t", startFake(t, s))
	inner := &handshakeDialer{Dialer: tcp.NewDialer(dialer.LoggerOption(logger.Default()))}
	d := xp2p.NewTunnelDialer(inner, provider)

	hs, ok := d.(dialer.Handshaker)
	if !ok {
		t.Fatal("tunnelDialer does not implement dialer.Handshaker (inner handshake would be skipped)")
	}
	conn, err := d.Dial(context.Background(), "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.Handshake(context.Background(), conn, dialer.AddrHandshakeOption("1.2.3.4:9999")); err != nil {
		t.Fatal(err)
	}
	if inner.addr != "1.2.3.4:9999" {
		t.Fatalf("handshake addr = %q, want the forwarded AddrHandshakeOption", inner.addr)
	}
	conn.Close()
}

func TestSupportedDialer(t *testing.T) {
	for _, name := range []string{"tcp", "tls", "ws", "mtcp", "mtls", "mws"} {
		if !xp2p.SupportedDialer(name) {
			t.Errorf("SupportedDialer(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"kcp", "quic", "grpc", "http2", ""} {
		if xp2p.SupportedDialer(name) {
			t.Errorf("SupportedDialer(%q) = true, want false (fail closed)", name)
		}
	}
}

// muxDialer implements dialer.Multiplexer to exercise the wrapper's
// Multiplex delegation (Chain.Route route-splitting depends on it).
type muxDialer struct {
	dialer.Dialer
	mux bool
}

func (d *muxDialer) Multiplex() bool { return d.mux }

func TestMultiplexDelegation(t *testing.T) {
	d := xp2p.NewTunnelDialer(&muxDialer{mux: true}, nil)
	m, ok := d.(dialer.Multiplexer)
	if !ok {
		t.Fatal("tunnelDialer does not implement dialer.Multiplexer")
	}
	if !m.Multiplex() {
		t.Fatal("Multiplex() = false for muxing inner, want true (route-splitting would not trigger)")
	}

	d2 := xp2p.NewTunnelDialer(&muxDialer{mux: false}, nil)
	if d2.(dialer.Multiplexer).Multiplex() {
		t.Fatal("Multiplex() = true for non-muxing inner, want false")
	}

	// tcp inner has no Multiplex method; the wrapper must report false.
	provider := NewGRPCPlugin("t", "127.0.0.1:1")
	d3 := xp2p.NewTunnelDialer(tcp.NewDialer(dialer.LoggerOption(logger.Default())), provider)
	if d3.(dialer.Multiplexer).Multiplex() {
		t.Fatal("Multiplex() = true for tcp inner, want false")
	}
}

// countingProvider is a TunnelProvider recording open/close calls.
type countingProvider struct {
	ln        net.Listener
	mu        sync.Mutex
	openCalls int
	closes    []string
}

func (p *countingProvider) OpenTunnel(ctx context.Context, peer string) (id, endpoint string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.openCalls++
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	p.ln = ln
	return fmt.Sprintf("t-%d", p.openCalls), ln.Addr().String(), nil
}

func (p *countingProvider) CloseTunnel(ctx context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes = append(p.closes, id)
	if p.ln != nil {
		p.ln.Close()
		p.ln = nil
	}
	return nil
}

func (p *countingProvider) Close() error { return nil }

func (p *countingProvider) openCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.openCalls
}

func (p *countingProvider) closeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.closes)
}

// noBaseDialer never touches its base net dialer — the mux session cache hit
// shape (mtcp.Dial returns the cached session conn directly).
type noBaseDialer struct{ dialer.Dialer }

func (d *noBaseDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go c1.Close()
	return c2, nil
}

// baseDialer dials its base net dialer once and returns the conn; if fail
// is set, it returns an error after the base dial succeeded.
type baseDialer struct {
	dialer.Dialer
	fail bool
}

func (d *baseDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}
	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if d.fail {
		conn.Close()
		return nil, errors.New("inner dial failed after base dial")
	}
	return conn, nil
}

func TestLazyOpenTunnel(t *testing.T) {
	// Cache hit: the inner never dials its base, so no tunnel is opened.
	p := &countingProvider{}
	d := xp2p.NewTunnelDialer(&noBaseDialer{}, p)
	conn, err := d.Dial(context.Background(), "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if n := p.openCount(); n != 0 {
		t.Fatalf("OpenTunnel calls = %d, want 0 (cache hit must not leak a tunnel)", n)
	}

	// Happy path: the inner dials its base exactly once; closing the conn
	// releases the tunnel.
	p2 := &countingProvider{}
	d2 := xp2p.NewTunnelDialer(&baseDialer{}, p2)
	conn2, err := d2.Dial(context.Background(), "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	if n := p2.openCount(); n != 1 {
		t.Fatalf("OpenTunnel calls = %d, want 1", n)
	}
	if n := p2.closeCount(); n != 0 {
		t.Fatalf("CloseTunnel calls before conn close = %d, want 0", n)
	}
	conn2.Close()
	if n := p2.closeCount(); n != 1 {
		t.Fatalf("CloseTunnel calls after conn close = %d, want 1", n)
	}

	// Failure path: inner.Dial fails after the base dial opened the tunnel;
	// the tunnel must be released (fail closed).
	p3 := &countingProvider{}
	d3 := xp2p.NewTunnelDialer(&baseDialer{fail: true}, p3)
	if _, err := d3.Dial(context.Background(), "127.0.0.1:9999"); err == nil {
		t.Fatal("Dial succeeded, want inner error")
	}
	if n := p3.openCount(); n != 1 {
		t.Fatalf("OpenTunnel calls = %d, want 1", n)
	}
	if n := p3.closeCount(); n != 1 {
		t.Fatalf("CloseTunnel calls after failed dial = %d, want 1 (fail closed)", n)
	}
}