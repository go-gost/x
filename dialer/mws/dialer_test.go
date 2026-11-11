package mws

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/listener"
	mws_listener "github.com/go-gost/x/listener/mws"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// echoServer serves mws on a local port and echoes every stream.
func echoServer(t *testing.T) string {
	t.Helper()
	ln := mws_listener.NewListener(
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

	md := d.(*mwsDialer)
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

	md := d.(*mwsDialer)
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
