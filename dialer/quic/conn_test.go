package quic

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/quictest"
)

func TestQuicConnCloseWriteKeepsReadSideOpen(t *testing.T) {
	srvTLS, cliTLS, err := quictest.SelfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}
	ln, addr, err := quictest.Listen(srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// The server reads the request until the client half-closes, then
	// answers.
	srvDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvDone <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			srvDone <- err
			return
		}
		if _, err := io.ReadAll(stream); err != nil {
			srvDone <- err
			return
		}
		_, err = stream.Write([]byte("response"))
		srvDone <- err
	}()

	sess, err := quictest.Dial(ctx, addr, cliTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.CloseWithError(0, "")

	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	qc := &quicConn{Stream: stream, laddr: sess.LocalAddr(), raddr: sess.RemoteAddr()}

	if _, err := qc.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}

	// CloseWrite must close only the send direction.
	cw, ok := interface{}(qc).(xio.CloseWrite)
	if !ok {
		t.Fatal("quicConn does not implement xio.CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	// The read side must still deliver the response.
	buf := make([]byte, 32)
	qc.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := qc.Read(buf)
	if err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if got := string(buf[:n]); got != "response" {
		t.Fatalf("read %q, want %q", got, "response")
	}

	if err := <-srvDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// appConn is the local application side of a pipe. It hands out its
// request bytes and then reports EOF, which is how an application that
// half-closes its side behaves.
type appConn struct {
	mu      sync.Mutex
	readBuf []byte
	readPos int
	written bytes.Buffer
}

func (c *appConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readPos >= len(c.readBuf) {
		return 0, io.EOF
	}
	n := copy(b, c.readBuf[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *appConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(b)
}

func (c *appConn) Close() error                       { return nil }
func (c *appConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *appConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *appConn) SetDeadline(t time.Time) error      { return nil }
func (c *appConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *appConn) SetWriteDeadline(t time.Time) error { return nil }

// An application that half-closes its side and then waits for the
// response must still get that response. Pipe's halfClose ends the write
// direction of the peer conn; it must not tear the read direction down.
func TestPipeHalfCloseKeepsTheResponse(t *testing.T) {
	srvTLS, cliTLS, err := quictest.SelfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}
	ln, addr, err := quictest.Listen(srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srvDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvDone <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			srvDone <- err
			return
		}
		// Read the request, then answer and close. The read may return
		// the request together with io.EOF, because the client half-closed
		// right after sending it.
		buf := make([]byte, 64)
		n, err := stream.Read(buf)
		if n == 0 && err != nil {
			srvDone <- err
			return
		}
		if _, err := stream.Write([]byte("response")); err != nil {
			srvDone <- err
			return
		}
		srvDone <- stream.Close()
	}()

	sess, err := quictest.Dial(ctx, addr, cliTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.CloseWithError(0, "")

	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	qc := &quicConn{Stream: stream, laddr: sess.LocalAddr(), raddr: sess.RemoteAddr()}

	// The application sends a request and then half-closes.
	app := &appConn{readBuf: []byte("request")}

	if err := xnet.Pipe(ctx, app, qc); err != nil {
		t.Fatalf("pipe: %v", err)
	}

	app.mu.Lock()
	got := app.written.String()
	app.mu.Unlock()
	if got != "response" {
		t.Fatalf("the application got %q, want %q", got, "response")
	}

	if err := <-srvDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}
