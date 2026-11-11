package http

import (
	"io"
	"net"
	"testing"

	xlogger "github.com/go-gost/x/logger"
)

// Data that follows the request body in the same read must not be lost.
func TestObfsHTTPConnDataAfterBody(t *testing.T) {
	client, server := net.Pipe()
	conn := &obfsHTTPConn{Conn: server, logger: xlogger.Nop()}

	go func() {
		defer client.Close()
		client.Write([]byte("GET / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Content-Length: 5\r\n" +
			"\r\n" +
			"hello" + "world"))
	}()

	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "helloworld" {
		t.Fatalf("got %q, want %q", b, "helloworld")
	}
}
