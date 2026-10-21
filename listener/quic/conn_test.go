package quic

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	xio "github.com/go-gost/x/internal/io"
	"github.com/go-gost/x/internal/util/quictest"
	"github.com/quic-go/quic-go"
)

// The server side of a QUIC stream must release the flow control credit of
// the data it never reads. Otherwise an aborted transfer keeps occupying
// the connection-level receive window until the peer cannot send anything
// on any stream, while the session itself stays alive.
//
// Cancelling the read side sends STOP_SENDING to the peer, which is the
// sender of the stream. The peer therefore learns about it by its writes
// failing.
func TestQuicConnCloseReadCancelsReadSide(t *testing.T) {
	qc, stream := newAcceptedConn(t)

	cr, ok := interface{}(qc).(xio.CloseRead)
	if !ok {
		t.Fatal("quicConn does not implement xio.CloseRead")
	}
	if err := cr.CloseRead(); err != nil {
		t.Fatal(err)
	}

	waitStopSending(t, stream)
}

// Close must cancel the read side as well, and additionally end the send
// direction, so that the peer sees the end of the stream.
func TestQuicConnCloseCancelsReadSide(t *testing.T) {
	qc, stream := newAcceptedConn(t)

	if err := qc.Close(); err != nil {
		t.Fatal(err)
	}

	waitStopSending(t, stream)

	// The peer also sees the end of the stream.
	buf := make([]byte, 64)
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("client read error = %v, want io.EOF", err)
	}
}

// waitStopSending waits until the peer observes the STOP_SENDING frame.
func waitStopSending(t *testing.T, stream *quic.Stream) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := stream.Write([]byte("more"))
		if err != nil {
			var streamErr *quic.StreamError
			if errors.As(err, &streamErr) {
				t.Logf("client observed: %v", err)
				return
			}
			t.Fatalf("client write error = %v (%T), want *quic.StreamError", err, err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout: the client never saw a STOP_SENDING")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newAcceptedConn starts a QUIC server, connects to it and opens a stream,
// so that the server side of the stream is a listener quicConn.
func newAcceptedConn(t *testing.T) (qc *quicConn, client *quic.Stream) {
	t.Helper()

	srvTLS, cliTLS, err := quictest.SelfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}
	ln, addr, err := quictest.Listen(srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	srvConn := make(chan *quicConn, 1)
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		srvConn <- &quicConn{Stream: stream, laddr: conn.LocalAddr(), raddr: conn.RemoteAddr()}
	}()

	sess, err := quictest.Dial(ctx, addr, cliTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.CloseWithError(0, "") })

	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// A QUIC stream only exists on the wire once data is sent on it.
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	select {
	case qc = <-srvConn:
	case err := <-srvErr:
		t.Fatalf("server: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: the server never accepted the stream")
	}

	return qc, stream
}
