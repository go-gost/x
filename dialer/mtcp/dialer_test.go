package mtcp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/listener"
	mtcp_listener "github.com/go-gost/x/listener/mtcp"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// echoServer serves mtcp on a local port and echoes every stream.
func echoServer(t *testing.T) string {
	t.Helper()
	ln := mtcp_listener.NewListener(
		listener.AddrOption("127.0.0.1:0"),
		listener.LoggerOption(xlogger.Nop()),
	)
	if err := ln.Init(xmd.NewMetadata(nil)); err != nil {
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
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// Concurrent requests that find no live session each dial a conn of their
// own, and a Dial that finds a session still waiting for its handshake
// replaces it. Both handshakes must still end on one usable session,
// whichever runs first; they used to fail with "unrecognized connection",
// or on a conn the later Dial had closed.
func TestHandshakeAfterAnotherDial(t *testing.T) {
	for _, first := range []string{"earlier", "later"} {
		t.Run(first+" conn first", func(t *testing.T) {
			addr := echoServer(t)
			d := NewDialer(
				dialer.LoggerOption(xlogger.Nop()),
			)
			if err := d.Init(xmd.NewMetadata(nil)); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()

			earlier, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
			if err != nil {
				t.Fatal(err)
			}
			later, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
			if err != nil {
				t.Fatal(err)
			}
			conns := []net.Conn{earlier, later}
			if first == "later" {
				conns = []net.Conn{later, earlier}
			}
			for i, conn := range conns {
				cc, err := d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
				if err != nil {
					t.Fatalf("handshake %d: %v", i+1, err)
				}
				if _, err := cc.Write([]byte("ping")); err != nil {
					t.Fatalf("handshake %d: write: %v", i+1, err)
				}
				if _, err := io.ReadFull(cc, make([]byte, 4)); err != nil {
					t.Fatalf("handshake %d: read: %v", i+1, err)
				}
				cc.Close()
			}
		})
	}
}

// blockingDialer blocks Dial for one address so a test can hold a dial open.
type blockingDialer struct {
	started chan struct{}
	release chan struct{}
	blocked string
}

func (d *blockingDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == d.blocked {
		close(d.started)
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

// A dial to one address must not wait for a slow dial to another: the TCP dial
// used to run under sessionMutex, so one unreachable node stalled every
// service sharing the chain.
func TestDialDoesNotWaitForAnotherAddress(t *testing.T) {
	d := NewDialer(dialer.LoggerOption(xlogger.Nop()))
	if err := d.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}

	bd := &blockingDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		blocked: "10.0.0.1:1",
	}
	defer close(bd.release)

	ctx := context.Background()
	go d.Dial(ctx, bd.blocked, dialer.NetDialerDialOption(bd))
	<-bd.started

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := d.Dial(ctx, "10.0.0.2:2", dialer.NetDialerDialOption(bd)); err != nil {
			return
		}
	}()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("a dial to another address waited for the blocked one")
	}
}

// A session dropped by the stall guard must not poison the dialer: the next
// handshake builds a new one and carries traffic again.
func TestHandshakeRebuildsAfterSessionClosed(t *testing.T) {
	addr := echoServer(t)
	d := NewDialer(dialer.LoggerOption(xlogger.Nop()))
	if err := d.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	roundTrip := func() {
		t.Helper()
		conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
		if err != nil {
			t.Fatal("dial: ", err)
		}
		cc, err := d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
		if err != nil {
			t.Fatal("handshake: ", err)
		}
		defer cc.Close()
		if _, err := cc.Write([]byte("ping")); err != nil {
			t.Fatal("write: ", err)
		}
		if _, err := io.ReadFull(cc, make([]byte, 4)); err != nil {
			t.Fatal("read: ", err)
		}
	}

	roundTrip()

	md := d.(*mtcpDialer)
	md.sessionMutex.Lock()
	session := md.sessions[addr]
	md.sessionMutex.Unlock()
	if session == nil {
		t.Fatal("no session cached after the first round trip")
	}
	session.Close()

	roundTrip()
}

// Dials and handshakes now run their network I/O outside sessionMutex, so they
// can overlap freely. However they interleave, they must still converge on a
// single session and every caller must get a working stream.
func TestConcurrentDialHandshakeConvergesOnOneSession(t *testing.T) {
	addr := echoServer(t)
	d := NewDialer(dialer.LoggerOption(xlogger.Nop()))
	if err := d.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
			if err != nil {
				errs <- err
				return
			}
			cc, err := d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
			if err != nil {
				errs <- err
				return
			}
			defer cc.Close()
			if _, err := cc.Write([]byte("ping")); err != nil {
				errs <- err
				return
			}
			if _, err := io.ReadFull(cc, make([]byte, 4)); err != nil {
				errs <- err
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	md := d.(*mtcpDialer)
	md.sessionMutex.Lock()
	defer md.sessionMutex.Unlock()
	if len(md.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(md.sessions))
	}
	for _, session := range md.sessions {
		if session.session == nil {
			t.Fatal("cached session was never established")
		}
	}
}

// stallingListener accepts TCP conns and never answers, so a TLS handshake
// through it hangs until the caller's context expires.
func stallingListener(t *testing.T) (string, <-chan struct{}) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			// Hold the conn open, unread and unanswered.
			_ = conn
		}
	}()

	return ln.Addr().String(), accepted
}

// A node that accepts TCP and then stalls its TLS handshake must not hold up
// dials to other addresses: session building is serialized per address, not
// across the whole dialer.
func TestHandshakeStallDoesNotBlockOtherAddresses(t *testing.T) {
	echoAddr := echoServer(t)
	stallAddr, accepted := stallingListener(t)

	d := NewDialer(
		dialer.LoggerOption(xlogger.Nop()),
	)
	if err := d.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	dialHandshake := func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
		if err != nil {
			return nil, err
		}
		return d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
	}

	if _, err := dialHandshake(ctx, echoAddr); err != nil {
		t.Fatal("warm up: ", err)
	}

	stallCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	go func() {
		if cc, err := dialHandshake(stallCtx, stallAddr); err == nil {
			cc.Close()
		}
	}()
	<-accepted
	time.Sleep(20 * time.Millisecond) // let the stalled handshake start

	start := time.Now()
	cc, err := dialHandshake(ctx, echoAddr)
	if err != nil {
		t.Fatal("dial while another address stalls: ", err)
	}
	defer cc.Close()
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("healthy address delayed %v behind a stalled handshake", d)
	}
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatal("write: ", err)
	}
	if _, err := io.ReadFull(cc, make([]byte, 4)); err != nil {
		t.Fatal("read: ", err)
	}
}

// gatedDialer hands out conns whose writes can be frozen, which stalls the mux
// send path of a real session.
type gatedDialer struct {
	mu   sync.Mutex
	gate chan struct{}
}

func (d *gatedDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd netDialer
	conn, err := nd.Dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &gatedConn{Conn: conn, d: d}, nil
}

func (d *gatedDialer) block(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v {
		if d.gate == nil {
			d.gate = make(chan struct{})
		}
		return
	}
	if d.gate != nil {
		close(d.gate)
		d.gate = nil
	}
}

type gatedConn struct {
	net.Conn
	d *gatedDialer
}

func (c *gatedConn) Write(b []byte) (int, error) {
	c.d.mu.Lock()
	gate := c.d.gate
	c.d.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return c.Conn.Write(b)
}

// The behaviour #925 is named after, end to end: a stalled send path makes
// stream writes time out, the guard retires the dialer's session, and the next
// dial builds a new tunnel that works.
func TestStalledWritesRetireTheSession(t *testing.T) {
	addr := echoServer(t)
	d := NewDialer(
		dialer.LoggerOption(xlogger.Nop()),
	)
	// A short stall window keeps the test quick; production waits 10s.
	if err := d.Init(xmd.NewMetadata(map[string]any{"mux.stallWindow": "10ms"})); err != nil {
		t.Fatal(err)
	}
	gd := &gatedDialer{}
	ctx := context.Background()

	roundTrip := func(deadline time.Duration) error {
		conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(gd))
		if err != nil {
			return err
		}
		cc, err := d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
		if err != nil {
			return err
		}
		defer cc.Close()
		if deadline > 0 {
			cc.SetWriteDeadline(time.Now().Add(deadline))
		}
		if _, err := cc.Write([]byte("ping")); err != nil {
			return err
		}
		_, err = io.ReadFull(cc, make([]byte, 4))
		return err
	}

	if err := roundTrip(0); err != nil {
		t.Fatal("first round trip: ", err)
	}

	conn, err := d.Dial(ctx, addr, dialer.NetDialerDialOption(gd))
	if err != nil {
		t.Fatal(err)
	}
	cc, err := d.(dialer.Handshaker).Handshake(ctx, conn, dialer.AddrHandshakeOption(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	gd.block(true)
	defer gd.block(false)
	for i := 1; i <= 2; i++ {
		cc.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := cc.Write([]byte("ping")); err == nil {
			t.Fatalf("write %d: expected a timeout", i)
		}
		time.Sleep(20 * time.Millisecond) // a window with no completed write
	}

	md := d.(*mtcpDialer)
	deadline := time.Now().Add(2 * time.Second)
	for {
		md.sessionMutex.Lock()
		session := md.sessions[addr]
		md.sessionMutex.Unlock()
		if session == nil || session.IsClosed() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stalled session was not retired")
		}
		time.Sleep(10 * time.Millisecond)
	}

	gd.block(false)
	if err := roundTrip(0); err != nil {
		t.Fatal("round trip after recovery: ", err)
	}
}
