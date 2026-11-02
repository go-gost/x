package h2_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/listener"
	dh2 "github.com/go-gost/x/dialer/http2/h2"
	lh2 "github.com/go-gost/x/listener/http2/h2"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
)

type netDialer struct{}

func (netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func newH2CListener(t *testing.T, addr string) listener.Listener {
	t.Helper()
	ln := lh2.NewListener(listener.AddrOption(addr), listener.LoggerOption(xlogger.Nop()))
	if err := ln.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	return ln
}

// serve accepts tunnel connections, greets each one with tag, then echoes.
func serve(ln listener.Listener, tag string) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := c.Write([]byte(tag)); err != nil {
					return
				}
				io.Copy(c, c)
			}()
		}
	}()
}

var errReadTimeout = errors.New("read timed out")

// readFull reads exactly n bytes from c, giving up after d.
// http2 tunnel connections do not support deadlines.
func readFull(c net.Conn, n int, d time.Duration) (string, error) {
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b := make([]byte, n)
		_, err := io.ReadFull(c, b)
		ch <- result{string(b), err}
	}()
	select {
	case r := <-ch:
		return r.s, r.err
	case <-time.After(d):
		return "", errReadTimeout
	}
}

func TestH2CListenerClose_NewStreamsReachReplacement(t *testing.T) {
	ln1 := newH2CListener(t, "127.0.0.1:0")
	addr := ln1.Addr().String()
	serve(ln1, "A")

	d := dh2.NewDialer(dialer.LoggerOption(xlogger.Nop()))
	if err := d.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	tryDial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return d.Dial(ctx, addr, dialer.NetDialerDialOption(netDialer{}))
	}

	held, err := tryDial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer held.Close()
	if s, err := readFull(held, 1, 3*time.Second); err != nil || s != "A" {
		t.Fatalf("before close: got %q, %v, want A", s, err)
	}

	// Simulate a config reload: the old listener is closed and a new one
	// is bound to the same address while the dialer keeps its HTTP/2 client.
	// The address must be free as soon as Close returns.
	ln1.Close()
	ln2 := newH2CListener(t, addr)
	defer ln2.Close()
	serve(ln2, "B")

	// A stream that races the GOAWAY may be refused, and the dialer cannot
	// replay its streaming body, so a dial is allowed to fail and be retried
	// (as the handler "retries" option would). It must never be accepted by
	// the old listener and then left without data.
	var got string
	for attempt := 0; attempt < 3 && got != "B"; attempt++ {
		c, err := tryDial()
		if err != nil {
			t.Logf("attempt %d: dial: %v", attempt, err)
			continue
		}
		s, err := readFull(c, 1, 3*time.Second)
		c.Close()
		if errors.Is(err, errReadTimeout) {
			t.Fatalf("attempt %d: new stream was accepted but got no data", attempt)
		}
		if err != nil {
			t.Fatalf("attempt %d: read: %v", attempt, err)
		}
		got = s
	}
	if got != "B" {
		t.Fatalf("after close: new streams got %q, want B from the new listener", got)
	}

	// A stream opened before the reload keeps working.
	if _, err := held.Write([]byte("x")); err != nil {
		t.Fatalf("held stream write: %v", err)
	}
	if s, err := readFull(held, 1, 3*time.Second); err != nil || s != "x" {
		t.Fatalf("held stream after close: got %q, %v, want x", s, err)
	}
}
