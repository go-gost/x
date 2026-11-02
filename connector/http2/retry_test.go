package http2_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/connector"
	http2connector "github.com/go-gost/x/connector/http2"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/internal/net/httptunnel"
	"github.com/go-gost/x/logger"
	"github.com/go-gost/x/metadata"
	xhttp2 "golang.org/x/net/http2"
)

// tunnelConn stands in for the conn the http2 dialer hands to the connector:
// its context carries the *http.Client that opens the tunnel.
type tunnelConn struct {
	addr string
	ctx  context.Context
}

func (c *tunnelConn) Context() context.Context         { return c.ctx }
func (c *tunnelConn) Read([]byte) (int, error)         { return 0, nil }
func (c *tunnelConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *tunnelConn) Close() error                     { return nil }
func (c *tunnelConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *tunnelConn) RemoteAddr() net.Addr             { return mustAddr(c.addr) }
func (c *tunnelConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

func mustAddr(addr string) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		panic(err)
	}
	return a
}

// echoTunnel accepts CONNECT and echoes the request body back.
func echoTunnel(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	f := w.(http.Flusher)
	f.Flush()
	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			f.Flush()
		}
		if err != nil {
			return
		}
	}
}

func startTunnelServer(t *testing.T, addr string, h http.HandlerFunc) (net.Listener, *http.Server) {
	t.Helper()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: h, Protocols: &protocols}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln, srv
}

// newTunnelClient returns an h2c client configured the way the http2 dialer
// configures the client it hands to this connector.
func newTunnelClient() *http.Client {
	return &http.Client{
		CheckRedirect: httptunnel.NoRedirect,
		Transport: &xhttp2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

func newTunnelConnector(t *testing.T) connector.Connector {
	t.Helper()

	c := http2connector.NewConnector(connector.LoggerOption(logger.Nop()))
	if err := c.Init(metadata.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	return c
}

func connectTunnel(ctx context.Context, c connector.Connector, client *http.Client, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ctx = ictx.ContextWithMetadata(ctx, metadata.NewMetadata(map[string]any{"client": client}))
	return c.Connect(ctx, &tunnelConn{addr: addr, ctx: ctx}, "tcp", "example.com:80")
}

// TestConnectRetriesOnNewConnection: when the server sends GOAWAY while
// CONNECTs are in flight, the transport retries them on a new connection. The
// retry must not reuse the tunnel body the first attempt closed
// (golang/go#82177).
func TestConnectRetriesOnNewConnection(t *testing.T) {
	const rounds, burst = 10, 20

	var bad []string
	for round := 0; round < rounds; round++ {
		ln1, srv1 := startTunnelServer(t, "127.0.0.1:0", echoTunnel)
		addr := ln1.Addr().String()
		c := newTunnelConnector(t)
		client := newTunnelClient()

		// Establish the cached HTTP/2 connection with a long-lived stream.
		held, err := connectTunnel(context.Background(), c, client, addr)
		if err != nil {
			t.Fatalf("round %d: connect: %v", round, err)
		}

		// Replace the server: GOAWAY on the old connection, a new server on
		// the same address for the retries to land on.
		ln1.Close()
		go srv1.Shutdown(context.Background())
		startTunnelServer(t, addr, echoTunnel)

		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var msg string
				if conn, err := connectTunnel(context.Background(), c, client, addr); err != nil {
					msg = "connect: " + err.Error()
				} else {
					if err := writeTunnel(conn, "ping", 3*time.Second); err != nil {
						msg = "connect succeeded, then: " + err.Error()
					}
					conn.Close()
				}
				if msg != "" {
					mu.Lock()
					bad = append(bad, msg)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		// Release the old stream so the old server's Shutdown can return.
		held.Close()
	}

	if len(bad) > 0 {
		kinds := map[string]int{}
		for _, m := range bad {
			kinds[failureKind(m)]++
		}
		t.Fatalf("%d of %d tunnels failed: %v", len(bad), rounds*burst, kinds)
	}
}

func failureKind(s string) string {
	for _, k := range []string{
		"read/write on closed pipe",
		"cannot rewind body",
		"define Request.GetBody",
		"timed out",
		"context deadline exceeded",
	} {
		if strings.Contains(s, k) {
			return k
		}
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// writeTunnel writes once to the tunnel and gives up after d. An HTTP/2 tunnel
// connection does not support deadlines, and a write to a pipe nobody reads
// blocks forever.
func writeTunnel(conn net.Conn, msg string, d time.Duration) error {
	ch := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte(msg))
		ch <- err
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		return errors.New("timed out")
	}
}
