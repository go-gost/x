package http2_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	http2connector "github.com/go-gost/x/connector/http2"
	http2dialer "github.com/go-gost/x/dialer/http2"
	"github.com/go-gost/x/logger"
	"github.com/go-gost/x/metadata"
)

const testWait = 3 * time.Second

type connectResult struct {
	conn net.Conn
	err  error
}

type testDialer struct{}

func (testDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func newProxy(t *testing.T, handler http.HandlerFunc, timeout time.Duration) func(context.Context, string) <-chan connectResult {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	// Dial performs a TCP-only preflight before establishing TLS.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	d := http2dialer.NewDialer(
		dialer.TLSConfigOption(srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()),
		dialer.LoggerOption(logger.Nop()),
	)
	if err := d.Init(metadata.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	c := http2connector.NewConnector(connector.LoggerOption(logger.Nop()))
	if err := c.Init(metadata.NewMetadata(map[string]any{"timeout": timeout.String()})); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, target string) <-chan connectResult {
		t.Helper()
		// Exercise cancellation in Connect, independently of the TCP preflight in Dial.
		conn, err := d.Dial(context.Background(), strings.TrimPrefix(srv.URL, "https://"), dialer.NetDialerDialOption(testDialer{}))
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan connectResult, 1)
		go func() {
			conn, err := c.Connect(ctx, conn, "tcp", target)
			result <- connectResult{conn: conn, err: err}
		}()
		return result
	}
}

func awaitConnect(t *testing.T, result <-chan connectResult) connectResult {
	t.Helper()
	select {
	case r := <-result:
		if r.conn != nil {
			t.Cleanup(func() { r.conn.Close() })
		}
		return r
	case <-time.After(testWait):
		t.Fatal("Connect did not return after establishment was canceled")
		return connectResult{}
	}
}

func awaitSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(testWait):
		t.Fatal(message)
	}
}

func TestConnectEstablishmentCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "deadline", "already-canceled"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			ended := make(chan struct{}, 1)
			timeout := time.Duration(0)
			if mode == "timeout" {
				timeout = 200 * time.Millisecond
			}
			connect := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				<-r.Context().Done() // Never send CONNECT response headers.
				ended <- struct{}{}
			}, timeout)
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			}
			defer cancel()
			if mode == "already-canceled" {
				cancel()
			}
			result := connect(ctx, "stall.example:443")
			if mode == "cancel" {
				awaitSignal(t, entered, "proxy did not receive CONNECT")
				cancel()
			}
			r := awaitConnect(t, result)
			want := context.Canceled
			if mode == "timeout" || mode == "deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(r.err, want) {
				t.Fatalf("Connect error = %v, want %v", r.err, want)
			}
			if mode != "already-canceled" {
				awaitSignal(t, ended, "proxy stream was not canceled")
			}
		})
	}
}

type flushWriter struct{ w http.ResponseWriter }

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.w.(http.Flusher).Flush()
	return n, err
}

func echo(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	io.Copy(flushWriter{w}, r.Body)
}

func exchange(t *testing.T, conn net.Conn) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		const message = "still connected"
		_, err := io.WriteString(conn, message)
		if err == nil {
			data := make([]byte, len(message))
			_, err = io.ReadFull(conn, data)
			if err == nil && string(data) != message {
				err = errors.New("echo mismatch")
			}
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testWait):
		t.Fatal("established tunnel stopped transferring data")
	}
}

func TestEstablishedTunnelOutlivesConnectContext(t *testing.T) {
	for _, timeout := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			connect := newProxy(t, echo, timeout)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			r := awaitConnect(t, connect(ctx, "echo.example:443"))
			if r.err != nil {
				t.Fatal(r.err)
			}
			exchange(t, r.conn)
			cancel()
			// Both the caller's deadline and the connector timeout expire while idle.
			time.Sleep(600 * time.Millisecond)
			exchange(t, r.conn)
		})
	}
}

func TestCanceledConnectPreservesEstablishedStream(t *testing.T) {
	addresses := make(chan string, 2)
	connect := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		addresses <- r.RemoteAddr
		if r.Host == "stall.example:443" {
			<-r.Context().Done()
			return
		}
		echo(w, r)
	}, 200*time.Millisecond)
	good := awaitConnect(t, connect(context.Background(), "echo.example:443"))
	if good.err != nil {
		t.Fatal(good.err)
	}
	exchange(t, good.conn)
	bad := awaitConnect(t, connect(context.Background(), "stall.example:443"))
	if !errors.Is(bad.err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", bad.err)
	}
	if first, second := <-addresses, <-addresses; first != second {
		t.Fatal("requests did not share an HTTP/2 connection")
	}
	exchange(t, good.conn)
}

func TestCloseUnblocksTunnelIO(t *testing.T) {
	ended := make(chan struct{})
	connect := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(ended)
	}, 0)
	r := awaitConnect(t, connect(context.Background(), "blocked.example:443"))
	if r.err != nil {
		t.Fatal(r.err)
	}
	readDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() { _, err := r.conn.Read(make([]byte, 1)); readDone <- err }()
	go func() { _, err := r.conn.Write(make([]byte, 16<<20)); writeDone <- err }()
	time.Sleep(50 * time.Millisecond)
	r.conn.Close()
	for _, done := range []<-chan error{readDone, writeDone} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("I/O unexpectedly succeeded after Close")
			}
		case <-time.After(testWait):
			t.Fatal("Close did not unblock I/O")
		}
	}
	awaitSignal(t, ended, "Close did not cancel the proxy stream")
}

func TestConnectWithoutTimeoutAllowsDelayedHeaders(t *testing.T) {
	connect := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		echo(w, r)
	}, 0)
	r := awaitConnect(t, connect(context.Background(), "echo.example:443"))
	if r.err != nil {
		t.Fatal(r.err)
	}
	exchange(t, r.conn)
}

func TestRejectedConnectCancelsStream(t *testing.T) {
	ended := make(chan struct{})
	connect := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(ended)
	}, 0)
	r := awaitConnect(t, connect(context.Background(), "auth.example:443"))
	if r.err == nil {
		t.Fatal("rejected CONNECT unexpectedly succeeded")
	}
	awaitSignal(t, ended, "rejected CONNECT stream was not canceled")
}
