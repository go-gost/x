package net

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// TestPipeHalfCloseUnblocksPendingWrite covers a peer that ends a smux v2
// stream while the client is still uploading.
//
// When the stream -> client direction reaches EOF, Pipe half-closes the client
// and bounds its reads with tcpWaitTimeout. The client -> stream direction,
// however, can be blocked in stream.Write waiting for a window update. A peer
// that has closed the stream drops further data and never sends that update,
// and smux (since it supports half-close) no longer wakes writers on FIN, so
// the write must be bounded as well. Otherwise Pipe never returns, the client
// connection is never read or closed, and its socket buffers stay pinned.
func TestPipeHalfCloseUnblocksPendingWrite(t *testing.T) {
	defer func(d time.Duration) { tcpWaitTimeout = d }(tcpWaitTimeout)
	tcpWaitTimeout = 200 * time.Millisecond

	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxStreamBuffer = 64 * 1024

	// Multiplexed upstream: the peer reads the request head, answers early and
	// closes the stream, like a server that rejects an upload.
	muxLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer muxLn.Close()
	peerDone := make(chan struct{})
	defer close(peerDone)
	go func() {
		c, err := muxLn.Accept()
		if err != nil {
			return
		}
		sess, err := smux.Server(c, cfg)
		if err != nil {
			c.Close()
			return
		}
		defer sess.Close()
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		io.ReadFull(st, make([]byte, 1024))
		st.Write([]byte("HTTP/1.1 413 Payload Too Large\r\n\r\n"))
		st.Close()
		<-peerDone
	}()

	muxConn, err := net.Dial("tcp", muxLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := smux.Client(muxConn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	// Client side: a TCP connection whose peer keeps uploading.
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()
	uploader, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer uploader.Close()
	client, err := clientLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	go func() {
		chunk := make([]byte, 32*1024)
		for i := 0; i < 128; i++ { // 4 MiB, well beyond the stream window
			if _, err := uploader.Write(chunk); err != nil {
				return
			}
		}
	}()
	go io.Copy(io.Discard, uploader)

	done := make(chan error, 1)
	go func() { done <- Pipe(context.Background(), client, stream) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		// Unblock the stuck goroutine so the test binary does not leak it.
		sess.Close()
		<-done
		t.Fatal("Pipe did not return after the peer closed the stream; the client -> stream write stayed blocked")
	}
}
