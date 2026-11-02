package h2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

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

func startH2C(t *testing.T, addr string, h http.HandlerFunc) (net.Listener, *http.Server) {
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

func newH2CDialer(t *testing.T) *h2Dialer {
	t.Helper()
	d := NewDialer(dialer.LoggerOption(xlogger.Nop())).(*h2Dialer)
	if err := d.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	return d
}

func dialH2C(d *h2Dialer, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
}

var errTimeout = errors.New("timed out")

// roundTrip writes msg to c and reads it back, giving up after d.
// http2 tunnel connections do not support deadlines.
func roundTrip(c net.Conn, msg string, d time.Duration) error {
	ch := make(chan error, 1)
	go func() {
		if _, err := c.Write([]byte(msg)); err != nil {
			ch <- err
			return
		}
		b := make([]byte, len(msg))
		if _, err := io.ReadFull(c, b); err != nil {
			ch <- err
			return
		}
		if string(b) != msg {
			ch <- errors.New("echo mismatch: " + string(b))
			return
		}
		ch <- nil
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		return errTimeout
	}
}

// TestDialRetriesOnNewConnection: when the server sends GOAWAY while dials
// are in flight, the transport retries them on a new connection. The retry
// must not reuse the tunnel body the first attempt closed (golang/go#82177),
// which shows up either as a failed dial ("read/write on closed pipe",
// "cannot rewind body", "define Request.GetBody") or as a dial that succeeds
// but whose write side is already closed.
func TestDialRetriesOnNewConnection(t *testing.T) {
	const rounds, burst = 20, 20

	var bad []string
	for round := 0; round < rounds; round++ {
		ln1, srv1 := startH2C(t, "127.0.0.1:0", echoTunnel)
		addr := ln1.Addr().String()
		d := newH2CDialer(t)
		dial := func() (net.Conn, error) { return dialH2C(d, addr) }

		// Establish the cached HTTP/2 connection with a long-lived stream.
		held, err := dial()
		if err != nil {
			t.Fatalf("round %d: dial: %v", round, err)
		}
		if err := roundTrip(held, "x", 3*time.Second); err != nil {
			t.Fatalf("round %d: held stream: %v", round, err)
		}

		// Replace the server: GOAWAY on the old connection, a new server on
		// the same address for the retries to land on.
		ln1.Close()
		go srv1.Shutdown(context.Background())
		startH2C(t, addr, echoTunnel)

		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var msg string
				if c, err := dial(); err != nil {
					msg = "dial: " + err.Error()
				} else {
					if err := roundTrip(c, "ping", 3*time.Second); err != nil {
						msg = "dial succeeded, then: " + err.Error()
					}
					c.Close()
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
			k := m
			if i := strings.Index(m, ": "); i >= 0 {
				k = m[:i] + ": " + failureKind(m[i+2:])
			}
			kinds[k]++
		}
		t.Fatalf("%d of %d tunnels failed: %v", len(bad), rounds*burst, kinds)
	}
}

func failureKind(s string) string {
	for _, k := range []string{"read/write on closed pipe", "cannot rewind body", "define Request.GetBody", "timed out"} {
		if strings.Contains(s, k) {
			return k
		}
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// TestDialDoesNotFollowRedirect: a tunnel must not be redirected. A followed
// redirect has no body, so the dial would return a connection whose write side
// is dead; a redirect loop would never return at all.
func TestDialDoesNotFollowRedirect(t *testing.T) {
	target, _ := startH2C(t, "127.0.0.1:0", echoTunnel)

	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			ln, _ := startH2C(t, "127.0.0.1:0", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://"+target.Addr().String()+"/", code)
			})

			err := dialError(t, newH2CDialer(t), ln.Addr().String())
			if err == nil {
				t.Fatal("dial followed the redirect, want an error")
			}
			if !strings.Contains(err.Error(), fmt.Sprint(code)) {
				t.Fatalf("dial: %v, want a %d error", err, code)
			}
		})
	}

	t.Run("loop", func(t *testing.T) {
		ln, _ := startH2C(t, "127.0.0.1:0", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host+"/next", http.StatusFound)
		})
		if err := dialError(t, newH2CDialer(t), ln.Addr().String()); err == nil {
			t.Fatal("dial followed a redirect loop, want an error")
		}
	})
}

// dialError dials and requires the call to return: a followed redirect would
// leave the dial waiting forever, as the tunnel context is not cancelled.
func dialError(t *testing.T, d *h2Dialer, addr string) error {
	t.Helper()

	ch := make(chan error, 1)
	go func() {
		c, err := dialH2C(d, addr)
		if c != nil {
			c.Close()
		}
		ch <- err
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not return")
		return nil
	}
}
