package probe

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
)

func TestHTTPProber(t *testing.T) {
	t.Run("200 OK", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			// Minimal HTTP/1.1 server — just respond 200 OK
			http.Serve(&singleConnListener{conn: server}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
		}()

		p := NewHTTPProber(&chain.ProbeConfig{
			HTTPPath:       "/health",
			HTTPHost:       "example.com",
			ExpectedStatus: http.StatusOK,
		})

		time.Sleep(50 * time.Millisecond) // let server start
		if err := p.Probe(client); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("wrong status", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			http.Serve(&singleConnListener{conn: server}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
		}()

		p := NewHTTPProber(&chain.ProbeConfig{
			HTTPPath:       "/",
			ExpectedStatus: http.StatusOK,
		})

		time.Sleep(50 * time.Millisecond)
		if err := p.Probe(client); err == nil {
			t.Fatal("expected error for 500 status, got nil")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		p := NewHTTPProber(&chain.ProbeConfig{
			Addr: "example.com:80",
		})
		if p.Path != "/" {
			t.Errorf("expected default path '/', got %q", p.Path)
		}
		if p.ExpectedStatus != http.StatusOK {
			t.Errorf("expected default status 200, got %d", p.ExpectedStatus)
		}
		if p.Host != "example.com:80" {
			t.Errorf("expected default host from Addr, got %q", p.Host)
		}
	})

	t.Run("connection error", func(t *testing.T) {
		server, client := net.Pipe()
		server.Close() // kill it immediately
		client.Close()

		p := NewHTTPProber(&chain.ProbeConfig{
			HTTPPath:       "/",
			ExpectedStatus: http.StatusOK,
		})
		if err := p.Probe(client); err == nil {
			t.Fatal("expected error on closed connection, got nil")
		}
	})
}

// singleConnListener is a net.Listener that returns a single pre-established
// connection, then returns an error for subsequent Accept calls.
type singleConnListener struct {
	conn   net.Conn
	closed bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, net.ErrClosed
	}
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	return nil, &net.OpError{} // block-like
}

func (l *singleConnListener) Close() error {
	l.closed = true
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
