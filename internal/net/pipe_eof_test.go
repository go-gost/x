package net

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
)

// dataWithEOFConn returns its whole payload together with io.EOF in a single
// Read call, like quic-go does for the last frame of a stream.
type dataWithEOFConn struct {
	payload []byte
	done    bool
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *dataWithEOFConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return 0, io.EOF
	}
	c.done = true
	return copy(p, c.payload), io.EOF
}

func (c *dataWithEOFConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(p)
}

func (c *dataWithEOFConn) Close() error { return nil }

func TestPipeKeepsDataReturnedWithEOF(t *testing.T) {
	src := &dataWithEOFConn{payload: []byte("HTTP/1.1 204 No Content\r\n\r\n")}
	dst := &dataWithEOFConn{done: true}

	if err := Pipe(context.Background(), src, dst); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if got := dst.written.String(); got != string(src.payload) {
		t.Fatalf("data returned with io.EOF was lost: got %q, want %q", got, src.payload)
	}
}
