package mux

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// A per-stream deadline must never reach the session conn underneath: the
// session is shared by every stream, so one stream's deadline would decide when
// the others may read. net/http makes this concrete — it parks a pending read
// with SetReadDeadline(time.Unix(1, 0)) to unblock it on teardown, and only
// clears that deadline when a read was actually in flight. A stream conn that
// passes the call through therefore leaves the session deadline in 1970, and
// the next Accept fails with an i/o timeout.
func TestStreamDeadlineStaysOnTheStream(t *testing.T) {
	for _, backend := range []struct {
		name   string
		client func(net.Conn) (Session, error)
		server func(net.Conn) (Session, error)
	}{
		{"smux", func(c net.Conn) (Session, error) { return ClientSession(c, &Config{Version: 2}) },
			func(c net.Conn) (Session, error) { return ServerSession(c, &Config{Version: 2}) }},
		{"yamux", func(c net.Conn) (Session, error) { return ClientSession(c, &Config{Type: "yamux"}) },
			func(c net.Conn) (Session, error) { return ServerSession(c, &Config{Type: "yamux"}) }},
	} {
		t.Run(backend.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()

			srvSession, err := backend.server(srv)
			if err != nil {
				t.Fatal(err)
			}
			defer srvSession.Close()

			cliSession, err := backend.client(cli)
			if err != nil {
				t.Fatal(err)
			}

			// One request served end to end over a stream, then the stream is
			// torn down the way net/http tears one down.
			stream, err := cliSession.GetConn()
			if err != nil {
				t.Fatal("open stream: ", err)
			}

			srvConn, err := srvSession.Accept()
			if err != nil {
				t.Fatal("accept stream: ", err)
			}
			go func() {
				io.WriteString(srvConn, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
				srvConn.Close()
			}()

			req, err := http.NewRequestWithContext(context.Background(), "GET", "http://x/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{
				Transport: &http.Transport{
					DialContext: func(context.Context, string, string) (net.Conn, error) { return stream, nil },
				},
			}).Do(req)
			if err != nil {
				t.Fatal("request: ", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal("read body: ", err)
			}
			if string(body) != "ok" {
				t.Fatalf("body = %q, want %q", body, "ok")
			}

			// net/http's teardown deadline: unblock a pending read by parking
			// it in the past, then clear it only if a read was in flight.
			stream.SetReadDeadline(time.Unix(1, 0))
			stream.SetReadDeadline(time.Time{})

			// The session must still hand out the next stream: its deadline was
			// never touched by the one that just closed.
			done := make(chan error, 1)
			go func() {
				_, err := cliSession.GetConn()
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("session unusable after a served stream: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("session hung after a served stream")
			}
		})
	}
}

// clientFor and serverFor bind a config to a backend constructor.
func clientFor(cfg *Config) func(net.Conn) (Session, error) {
	return func(c net.Conn) (Session, error) { return ClientSession(c, cfg) }
}

func serverFor(cfg *Config) func(net.Conn) (Session, error) {
	return func(c net.Conn) (Session, error) { return ServerSession(c, cfg) }
}

func smuxConfig() *Config  { return &Config{Version: 2} }
func yamuxConfig() *Config { return &Config{Type: "yamux"} }

// stallConn is a session conn whose Write can be frozen, so frames handed to it
// never reach the peer. That is the only externally visible difference between
// a healthy send path and one the peer has stopped draining: the socket stays
// open, the peer keeps sending, and only the writes stop completing.
type stallConn struct {
	net.Conn
	mu   sync.Mutex
	gate chan struct{}
}

func newStallConn(c net.Conn) *stallConn {
	return &stallConn{Conn: c}
}

// block freezes further writes; unblock releases the ones already frozen.
func (c *stallConn) block(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if v {
		if c.gate == nil {
			c.gate = make(chan struct{})
		}
		return
	}
	if c.gate != nil {
		close(c.gate)
		c.gate = nil
	}
}

func (c *stallConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	gate := c.gate
	c.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return c.Conn.Write(b)
}

// stalledSession pairs a client and a server session over a stallable conn and
// returns the client session, one open stream, and the stall switch.
func stalledSession(t *testing.T, client, server func(net.Conn) (Session, error)) (Session, net.Conn, *stallConn) {
	t.Helper()

	p1, p2 := net.Pipe()
	sc := newStallConn(p1)
	srv, err := server(p2)
	if err != nil {
		t.Fatal("server session: ", err)
	}
	cli, err := client(sc)
	if err != nil {
		t.Fatal("client session: ", err)
	}

	stream, err := cli.GetConn()
	if err != nil {
		t.Fatal("open stream: ", err)
	}

	go func() {
		for {
			conn, err := srv.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, conn)
		}
	}()

	// Cleanups run last registered first: release the conn before closing the
	// stream (whose FIN would otherwise wait out smux's open-close timeout on a
	// frozen conn), and close the sessions last.
	t.Cleanup(func() {
		cli.Close()
		srv.Close()
		p2.Close()
	})
	t.Cleanup(func() { stream.Close() })
	t.Cleanup(sc.unblock)

	return cli, stream, sc
}

func (c *stallConn) unblock() { c.block(false) }

func waitSessionClosed(t *testing.T, s Session) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.IsClosed() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("session stayed open")
}

// stallConfig shortens the stall window so the tests do not have to wait out
// the production ten seconds of silence.
func stallConfig() *Config {
	return &Config{Version: 2, StallWindow: 10 * time.Millisecond}
}

// A stream write that times out is the only signal a stalled send path gives:
// the session stays open (its keepalive tracks received frames only) and every
// later stream stalls on it. Two in a row, with no successful write in
// between, must close the session so its owner rebuilds the tunnel.
func TestSessionClosesAfterRepeatedWriteTimeouts(t *testing.T) {
	cli, stream, sc := stalledSession(t, clientFor(stallConfig()), serverFor(smuxConfig()))
	sc.block(true)
	defer sc.block(false)

	for i := 1; i <= 2; i++ {
		if err := stream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Write(make([]byte, 1024))
		if err == nil {
			t.Fatalf("write %d: expected a timeout", i)
		}
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("write %d: err = %v, want a timeout", i, err)
		}
		// A session is condemned only after a window with no completed write.
		time.Sleep(2 * stallConfig().StallWindow)
	}

	waitSessionClosed(t, cli)
}

// One timeout proves nothing on its own: a successful write in between clears
// the strike, so only a second consecutive one condemns the session.
func TestSessionSurvivesSingleWriteTimeout(t *testing.T) {
	cli, stream, sc := stalledSession(t, clientFor(stallConfig()), serverFor(smuxConfig()))

	sc.block(true)
	if err := stream.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(make([]byte, 1024)); err == nil {
		t.Fatal("expected a timeout")
	}

	sc.block(false)
	if err := stream.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal("write after release: ", err)
	}

	sc.block(true)
	defer sc.block(false)
	if err := stream.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(make([]byte, 1024)); err == nil {
		t.Fatal("expected a second timeout")
	}

	if cli.IsClosed() {
		t.Fatal("session closed on a single new strike")
	}
}

// yamux reports a stalled conn as ErrConnectionWriteTimeout, and then blocks
// the next write of that stream forever, so the error is final on its own. It
// surfaces after yamux's own 10s connection write timeout, so this asserts the
// reaction rather than driving a real session into it.
func TestYamuxConnectionWriteTimeoutClosesSession(t *testing.T) {
	closed := make(chan struct{})
	stall := &sessionStall{close: func() error {
		close(closed)
		return nil
	}}

	stall.observe(yamux.ErrConnectionWriteTimeout)

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("session left open after a connection write timeout")
	}
}

// A session that has one strike is not closed until the next timed-out write.
func TestSessionStallIgnoresNonTimeoutErrors(t *testing.T) {
	stall := &sessionStall{close: func() error {
		t.Error("session closed on a non-timeout error")
		return nil
	}}

	stall.observe(io.ErrClosedPipe)
	stall.observe(errors.New("boom"))
}

// openBlockedSession returns a client session whose peer never reads, so a SYN
// frame cannot be written and the open hangs exactly like a stalled tunnel.
func openBlockedSession(t *testing.T, cfg *Config) Session {
	t.Helper()

	p1, p2 := net.Pipe()
	cli, err := ClientSession(p1, cfg)
	if err != nil {
		t.Fatal("client session: ", err)
	}
	t.Cleanup(func() {
		cli.Close()
		p2.Close()
	})
	return cli
}

// A stalled open must return when the caller's context expires instead of
// waiting out the backend's own SYN timer (smux 30s, yamux 75s).
func TestGetConnContextHonoursContextDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *Config
	}{
		{"smux", smuxConfig()},
		{"yamux", yamuxConfig()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli := openBlockedSession(t, tc.config)

			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()

			start := time.Now()
			_, err := cli.GetConnContext(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v, want context.DeadlineExceeded", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("open returned after %v, want the context deadline", d)
			}
		})
	}
}

// With no context deadline the configured open timeout is the backstop.
func TestGetConnContextUsesOpenTimeout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *Config
	}{
		{"smux", &Config{Version: 2, OpenTimeout: 300 * time.Millisecond}},
		{"yamux", &Config{Type: "yamux", OpenTimeout: 300 * time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli := openBlockedSession(t, tc.config)

			start := time.Now()
			_, err := cli.GetConnContext(context.Background())
			if !errors.Is(err, ErrOpenTimeout) {
				t.Fatalf("err = %v, want ErrOpenTimeout", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("open returned after %v, want the open timeout", d)
			}
		})
	}
}

// A healthy session still opens a usable stream.
func TestGetConnStillOpensOnHealthySession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *Config
	}{
		{"smux", smuxConfig()},
		{"yamux", yamuxConfig()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, _, _ := stalledSession(t, clientFor(tc.config), serverFor(tc.config))

			conn, err := cli.GetConnContext(context.Background())
			if err != nil {
				t.Fatal("open: ", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal("write: ", err)
			}
		})
	}
}

// Two strikes are not enough while the session is still busy: a peer that
// consumes slowly produces write timeouts on one stream while others complete,
// and closing the session there would reset every stream multiplexed on it.
func TestSessionStallRequiresSilence(t *testing.T) {
	closed := make(chan struct{})
	stall := newSessionStall(time.Hour, func() error {
		close(closed)
		return nil
	})

	stall.observe(timeoutErr{})
	stall.observe(timeoutErr{})

	select {
	case <-closed:
		t.Fatal("busy session closed")
	case <-time.After(50 * time.Millisecond):
	}

	// The same strikes do condemn a session that has been silent for the
	// whole window.
	stall = newSessionStall(time.Nanosecond, func() error {
		close(closed)
		return nil
	})
	stall.observe(timeoutErr{})
	stall.observe(timeoutErr{})

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("silent session not closed")
	}
}

// timeoutErr is a net.Error with Timeout() true, as the backends report a
// stream write that missed its deadline.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
