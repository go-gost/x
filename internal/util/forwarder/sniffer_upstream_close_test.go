package forwarder

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/x/internal/util/sniffing"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"
)

// startRawUpstream starts a raw TCP upstream and hands its first accepted
// connection to handle. The listener is closed when the test finishes; the
// connection is owned by the handler and asserted by the test.
func startRawUpstream(t *testing.T, handle func(net.Conn)) (string, <-chan net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		cc, err := ln.Accept()
		ln.Close() // one connection per iteration; keeps the fd count flat
		if err != nil {
			return
		}
		accepted <- cc
		handle(cc)
	}()
	return ln.Addr().String(), accepted
}

// startSniffer hands the server side of a net.Pipe to HandleHTTP and returns
// the client side plus a completion signal.
func startSniffer(t *testing.T, upstreamAddr string) (net.Conn, <-chan error) {
	t.Helper()

	h := &Sniffer{ReadTimeout: 5 * time.Second}
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	done := make(chan error, 1)
	go func() {
		done <- h.HandleHTTP(context.Background(), serverConn,
			sniffing.WithService("test"),
			sniffing.WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstreamAddr)
			}),
			sniffing.WithRecorderObject(&xrecorder.HandlerRecorderObject{}),
			sniffing.WithLog(xlogger.Nop()),
		)
	}()
	return clientConn, done
}

func waitAccepted(t *testing.T, accepted <-chan net.Conn) net.Conn {
	t.Helper()

	select {
	case cc := <-accepted:
		return cc
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not accepted")
		return nil
	}
}

func waitHandleDone(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleHTTP did not return")
	}
}

// assertConnClosed fails unless cc has been closed by its owner: a read must
// report EOF rather than a deadline timeout.
func assertConnClosed(t *testing.T, cc net.Conn) {
	t.Helper()
	defer cc.Close()

	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := cc.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("upstream conn still open after HandleHTTP returned")
	}
	if os.IsTimeout(err) {
		t.Fatalf("upstream conn not closed after HandleHTTP returned: %v", err)
	}
}

func assertUpstreamClosedAfterResponse(t *testing.T) {
	t.Helper()

	addr, accepted := startRawUpstream(t, func(cc net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(cc)); err != nil {
			return
		}
		io.WriteString(cc, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
		// Keep the connection open; HandleHTTP must close it.
	})

	client, done := startSniffer(t, addr)
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	client.Close()

	waitHandleDone(t, done)
	assertConnClosed(t, waitAccepted(t, accepted))
}

func assertUpstreamClosedAfterStreamDisconnect(t *testing.T) {
	t.Helper()

	clientClosed := make(chan struct{})
	addr, accepted := startRawUpstream(t, func(cc net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(cc)); err != nil {
			return
		}
		// Streaming response: one chunk only, no terminating chunk, keep open.
		io.WriteString(cc, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ndata: x\n\r\n")

		// The proxy blocks reading the upstream body, so a silent upstream
		// never notices the client is gone. A second chunk after the client
		// closes makes the next write fail, which returns from HandleHTTP.
		<-clientClosed
		io.WriteString(cc, "8\r\ndata: y\n\r\n")
	})

	client, done := startSniffer(t, addr)
	req, _ := http.NewRequest("GET", "http://example.com/v1/messages", nil)
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.Body.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}

	// Simulate the client disconnecting mid-stream.
	client.Close()
	resp.Body.Close()
	close(clientClosed)

	waitHandleDone(t, done)
	assertConnClosed(t, waitAccepted(t, accepted))
}

func TestHandleHTTP_ClosesUpstreamAfterResponse(t *testing.T) {
	assertUpstreamClosedAfterResponse(t)
}

func TestHandleHTTP_ClosesUpstreamAfterStreamDisconnect(t *testing.T) {
	assertUpstreamClosedAfterStreamDisconnect(t)
}

// TestHandleHTTP_UpstreamConnClosedManyTimes repeats the close assertion to
// catch leaks that only show up across many requests.
func TestHandleHTTP_UpstreamConnClosedManyTimes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-iteration close check in short mode")
	}
	for i := 0; i < 1000; i++ {
		assertUpstreamClosedAfterStreamDisconnect(t)
	}
}

func TestHandleHTTP_ClosesUpstreamWhenClientLeavesSilentStream(t *testing.T) {
	old := upstreamBodyIdleTimeout
	upstreamBodyIdleTimeout = 100 * time.Millisecond
	defer func() { upstreamBodyIdleTimeout = old }()

	addr, accepted := startRawUpstream(t, func(cc net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(cc)); err != nil {
			return
		}
		// One chunk, then stay silent: no write fails, so only the idle
		// deadline can unblock the handler after the client disconnects.
		io.WriteString(cc, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ndata: x\n\r\n")
	})

	client, done := startSniffer(t, addr)
	if _, err := io.WriteString(client, "GET /v1/messages HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	// Read every byte the proxy writes (including the chunk terminator) so the
	// handler is left blocked on the upstream read when the client goes away.
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	buf := make([]byte, 4096)
	for !strings.Contains(string(got), "data: x\n\r\n") {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	client.SetReadDeadline(time.Time{})
	client.Close()

	waitHandleDone(t, done)
	assertConnClosed(t, waitAccepted(t, accepted))
}
