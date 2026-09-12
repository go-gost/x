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
	"github.com/go-gost/x/dialer/udp"
	xlogger "github.com/go-gost/x/logger"
	xp2p "github.com/go-gost/x/p2p"
	"github.com/go-gost/x/p2p/streamconn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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
// peer and allocates the tunnel id (no endpoint — the data plane is the
// Tunnel stream); Tunnel serves that stream, bridged to the target (tcp) or
// framed-echoed (udp). A record is removed when its Tunnel handler returns:
// stream end IS the tunnel teardown. bizFail answers ok:false with a gRPC
// status OK.
type fakeServer struct {
	proto.UnimplementedP2PServer
	mu       sync.Mutex
	seq      atomic.Int64
	tunnels  map[string]fakeTunnel
	networks []string // network of every OpenTunnel request, in order
	bizFail  bool
}

type fakeTunnel struct {
	network string
	target  string
}

func newFakeServer() *fakeServer {
	return &fakeServer{tunnels: make(map[string]fakeTunnel)}
}

func (s *fakeServer) OpenTunnel(ctx context.Context, req *proto.OpenTunnelRequest) (*proto.OpenTunnelReply, error) {
	host, port, err := net.SplitHostPort(req.Peer)
	if err != nil || host == "" || port == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q", req.Peer)
	}
	s.mu.Lock()
	s.networks = append(s.networks, req.Network)
	s.mu.Unlock()
	if s.bizFail {
		return &proto.OpenTunnelReply{Ok: false, Error: "biz boom"}, nil
	}
	network := req.Network
	if network == "" {
		network = "tcp"
	}
	id := fmt.Sprintf("t-%d", s.seq.Add(1))
	s.mu.Lock()
	s.tunnels[id] = fakeTunnel{network: network, target: req.Peer}
	s.mu.Unlock()
	return &proto.OpenTunnelReply{Ok: true, Id: id}, nil
}

// Tunnel is the data plane: look the tunnel up by the "id" metadata key
// (unknown → NotFound), then serve the stream. The host side of the stream
// stays raw; in udp mode the framing is carried end to end as bytes (the
// fake plays the framed peer).
func (s *fakeServer) Tunnel(stream proto.P2P_TunnelServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	var id string
	if v := md.Get("id"); len(v) > 0 {
		id = v[0]
	}
	s.mu.Lock()
	t, ok := s.tunnels[id]
	s.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "unknown tunnel id")
	}
	defer func() {
		s.mu.Lock()
		delete(s.tunnels, id)
		s.mu.Unlock()
	}()

	if t.network == "udp" {
		c := streamconn.New(stream, nil, "udp", nil, nil)
		defer c.Close()
		buf := make([]byte, streamconn.MaxFrame)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return nil // client closed: normal teardown
			}
			if _, err := c.Write(buf[:n]); err != nil {
				return nil
			}
		}
	}

	up, err := net.DialTimeout("tcp", t.target, 5*time.Second)
	if err != nil {
		return err
	}
	defer up.Close()
	down := streamconn.New(stream, nil, "tcp", nil, nil)
	defer down.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, down)
		up.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(down, up)
		down.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	return nil
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

// networkOf returns the network of the i-th OpenTunnel request.
func (s *fakeServer) networkOf(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.networks) {
		return ""
	}
	return s.networks[i]
}

func waitTunnelCount(t *testing.T, s *fakeServer, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.tunnelCount() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("tunnel count = %d, want %d", s.tunnelCount(), want)
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
	s := newFakeServer()
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
	// The record is removed when the host-side handler returns (stream end).
	waitTunnelCount(t, s, 0)
	// second Close must be a no-op (idempotent), not an error or panic
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count after double close = %d, want 0", n)
	}
}

// TestDialReadDeadline proves the tunnel conn honors SetReadDeadline (the
// reason the conn exists in this shape: inner tls/ws handshakes set deadlines
// and ignore the error, so a silent peer must not hang a Read forever).
func TestDialReadDeadline(t *testing.T) {
	s := newFakeServer()
	d, _ := newTestDialer(t, s)
	target := startEcho(t)

	conn, err := d.Dial(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := conn.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("Read returned after %v, want the deadline to have applied", elapsed)
	}

	// Clearing the deadline restores normal reads.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	echoOnce(t, conn)
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

func TestDialConcurrent(t *testing.T) {
	s := newFakeServer()
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
	waitTunnelCount(t, s, 0)
}

func TestOpenTunnelInvalidPeer(t *testing.T) {
	s := newFakeServer()
	d, _ := newTestDialer(t, s)

	if _, err := d.Dial(context.Background(), "foo"); err == nil {
		t.Fatal("Dial succeeded, want invalid-peer error")
	}
	if n := s.tunnelCount(); n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

func TestOpenTunnelBizFail(t *testing.T) {
	s := newFakeServer()
	s.bizFail = true
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
	s := newFakeServer()
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
	for _, name := range []string{"tcp", "tls", "ws", "mtcp", "mtls", "mws", "udp"} {
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

// TestUDPNetworkPassthrough covers the datagram shape end to end over the
// gRPC seam: a udp inner dialer must make the plugin open a udp tunnel
// (network carried on the request), the wrapped conn must preserve datagram
// boundaries, and the dial result must expose the PacketConn shape the tun
// handler's transport expects.
func TestUDPNetworkPassthrough(t *testing.T) {
	s := newFakeServer()
	provider := NewGRPCPlugin("t", startFake(t, s))
	inner := udp.NewDialer(dialer.LoggerOption(logger.Default()))
	d := xp2p.NewTunnelDialer(inner, provider)

	conn, err := d.Dial(context.Background(), "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if got := s.networkOf(0); got != "udp" {
		t.Fatalf("OpenTunnel network = %q, want udp", got)
	}
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatal("udp dial result is not a net.PacketConn")
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("datagram round trip = %q, %v; want ping", buf[:n], err)
	}
	// Boundaries preserved: consecutive datagrams never coalesce.
	conn.Write([]byte("a"))
	conn.Write([]byte("bb"))
	if n, err := conn.Read(buf); err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("Read = %q, %v; want single-byte datagram", buf[:n], err)
	}
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "bb" {
		t.Fatalf("Read = %q, %v; want bb (no coalescing)", buf[:n], err)
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

// countingProvider is a TunnelProvider recording opens/closes and the network
// each open asked for. Each open returns an in-memory conn.
type countingProvider struct {
	mu        sync.Mutex
	openCalls int
	closeCall int
	networks  []string
}

func (p *countingProvider) OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error) {
	p.mu.Lock()
	p.openCalls++
	p.networks = append(p.networks, network)
	p.mu.Unlock()
	c1, c2 := net.Pipe()
	go c1.Close()
	return &countingConn{Conn: c2, onClose: func() {
		p.mu.Lock()
		p.closeCall++
		p.mu.Unlock()
	}}, nil
}

// countingConn observes the tunnel conn's close (the tunnel teardown).
type countingConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *countingConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

func (p *countingProvider) networkOf(i int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= len(p.networks) {
		return ""
	}
	return p.networks[i]
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
	return p.closeCall
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
		t.Fatalf("OpenTunnelStream calls = %d, want 0 (cache hit must not leak a tunnel)", n)
	}

	// Happy path: the inner dials its base exactly once; closing the conn
	// tears the tunnel down (the stream ending IS the teardown).
	p2 := &countingProvider{}
	d2 := xp2p.NewTunnelDialer(&baseDialer{}, p2)
	conn2, err := d2.Dial(context.Background(), "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	if n := p2.openCount(); n != 1 {
		t.Fatalf("OpenTunnelStream calls = %d, want 1", n)
	}
	if got := p2.networkOf(0); got != "tcp" {
		t.Fatalf("OpenTunnel network = %q, want tcp for a stream inner", got)
	}
	if n := p2.closeCount(); n != 0 {
		t.Fatalf("conn closes before conn2 close = %d, want 0", n)
	}
	conn2.Close()
	if n := p2.closeCount(); n != 1 {
		t.Fatalf("conn closes after conn2 close = %d, want 1", n)
	}

	// Failure path: inner.Dial fails after the base dial opened the tunnel;
	// the tunnel must be released (fail closed).
	p3 := &countingProvider{}
	d3 := xp2p.NewTunnelDialer(&baseDialer{fail: true}, p3)
	if _, err := d3.Dial(context.Background(), "127.0.0.1:9999"); err == nil {
		t.Fatal("Dial succeeded, want inner error")
	}
	if n := p3.openCount(); n != 1 {
		t.Fatalf("OpenTunnelStream calls = %d, want 1", n)
	}
	if n := p3.closeCount(); n != 1 {
		t.Fatalf("conn closes after failed dial = %d, want 1 (fail closed)", n)
	}
}
