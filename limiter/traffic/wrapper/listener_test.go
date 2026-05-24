package wrapper

import (
	"errors"
	"net"
	"testing"

	traffic "github.com/go-gost/core/limiter/traffic"
)

type testListener struct {
	connCh chan net.Conn
	addr   net.Addr
}

func (l *testListener) Accept() (net.Conn, error) {
	c, ok := <-l.connCh
	if !ok {
		return nil, errors.New("listener closed")
	}
	return c, nil
}

func (l *testListener) Close() error {
	close(l.connCh)
	return nil
}

func (l *testListener) Addr() net.Addr { return l.addr }

func TestWrapListener_NilLimiter(t *testing.T) {
	ln := &testListener{}
	result := WrapListener("svc", ln, nil)
	if result != ln {
		t.Fatal("nil limiter should return original listener")
	}
}

func TestAccept_WrapsConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ln := &testListener{
		connCh: make(chan net.Conn, 1),
		addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	}
	ln.connCh <- client

	tl := &mockTrafficLimiter{inLim: &mockLimiter{limit: 1000}}
	wrappedLn := WrapListener("test-svc", ln, tl)

	conn, err := wrappedLn.Accept()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := conn.(*limitConn); !ok {
		t.Fatalf("accepted conn should be *limitConn, got %T", conn)
	}
}

var (
	_ traffic.TrafficLimiter = (*mockTrafficLimiter)(nil)
)
