package mux

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// A per-stream deadline must never reach the session conn underneath: the
// session is shared by every stream, so one stream's deadline would decide when
// the others may read. net/http makes this concrete — it parks a pending read
// with SetReadDeadline(time.Unix(1, 0)) to unblock it on teardown, and only
// clears that deadline when a read was actually in flight. A stream conn that
// passes the call through therefore leaves the session deadline in 1970, and
// the next Accept fails with an i/o timeout.
func TestStreamDeadlineStaysOnTheStream(t *testing.T) {
	for _, backend := range []struct {
		name   string
		client func(net.Conn) (Session, error)
		server func(net.Conn) (Session, error)
	}{
		{"smux", func(c net.Conn) (Session, error) { return ClientSession(c, &Config{Version: 2}) },
			func(c net.Conn) (Session, error) { return ServerSession(c, &Config{Version: 2}) }},
		{"yamux", func(c net.Conn) (Session, error) { return ClientSession(c, &Config{Type: "yamux"}) },
			func(c net.Conn) (Session, error) { return ServerSession(c, &Config{Type: "yamux"}) }},
	} {
		t.Run(backend.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()

			srvSession, err := backend.server(srv)
			if err != nil {
				t.Fatal(err)
			}
			defer srvSession.Close()

			cliSession, err := backend.client(cli)
			if err != nil {
				t.Fatal(err)
			}

			// One request served end to end over a stream, then the stream is
			// torn down the way net/http tears one down.
			stream, err := cliSession.GetConn()
			if err != nil {
				t.Fatal("open stream: ", err)
			}

			srvConn, err := srvSession.Accept()
			if err != nil {
				t.Fatal("accept stream: ", err)
			}
			go func() {
				io.WriteString(srvConn, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
				srvConn.Close()
			}()

			req, err := http.NewRequestWithContext(context.Background(), "GET", "http://x/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{
				Transport: &http.Transport{
					DialContext: func(context.Context, string, string) (net.Conn, error) { return stream, nil },
				},
			}).Do(req)
			if err != nil {
				t.Fatal("request: ", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal("read body: ", err)
			}
			if string(body) != "ok" {
				t.Fatalf("body = %q, want %q", body, "ok")
			}

			// net/http's teardown deadline: unblock a pending read by parking
			// it in the past, then clear it only if a read was in flight.
			stream.SetReadDeadline(time.Unix(1, 0))
			stream.SetReadDeadline(time.Time{})

			// The session must still hand out the next stream: its deadline was
			// never touched by the one that just closed.
			done := make(chan error, 1)
			go func() {
				_, err := cliSession.GetConn()
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("session unusable after a served stream: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("session hung after a served stream")
			}
		})
	}
}