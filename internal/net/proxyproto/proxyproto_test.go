package proxyproto

import (
	"net"
	"testing"
	"time"

	xio "github.com/go-gost/x/internal/io"
	proxyproto "github.com/pires/go-proxyproto"
)

type testConn struct {
	net.Conn
}

func (c *testConn) Close() error            { return nil }
func (c *testConn) RemoteAddr() net.Addr    { return &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234} }
func (c *testConn) LocalAddr() net.Addr     { return &net.TCPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 5678} }
func (c *testConn) CloseRead() error        { return xio.ErrUnsupported }
func (c *testConn) CloseWrite() error       { return xio.ErrUnsupported }

type testListener struct {
	net.Listener
}

func (l *testListener) Accept() (net.Conn, error) {
	return &testConn{}, nil
}

func (l *testListener) Close() error   { return nil }
func (l *testListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestWrapListener_NoProxyProto(t *testing.T) {
	ln := &testListener{}
	result := WrapListener(0, ln, 0)
	if result != ln {
		t.Error("expected original listener when ppv=0")
	}
}

func TestWrapListener_WithProxyProto(t *testing.T) {
	ln := &testListener{}
	result := WrapListener(1, ln, 5*time.Second)
	if result == ln {
		t.Error("expected wrapped listener when ppv>0")
	}
	_, ok := result.(*listener)
	if !ok {
		t.Errorf("expected *listener, got %T", result)
	}
}

func Test_serverConn_Context(t *testing.T) {
	conn := &testConn{}
	sc := &serverConn{Conn: conn}
	if sc.Context() != nil {
		// When no context set, it should be nil
		_ = sc.Context()
	}
}

func TestWrapClientConn_NoProxyProto(t *testing.T) {
	c := &testConn{}
	result := WrapClientConn(0, nil, nil, c)
	if result != c {
		t.Error("expected original conn when ppv=0")
	}
}

func TestWrapClientConn_NilConn(t *testing.T) {
	result := WrapClientConn(1, nil, nil, nil)
	if result != nil {
		t.Error("expected nil for nil conn")
	}
}

func TestWrapClientConn_NilSrc(t *testing.T) {
	c := &testConn{}
	result := WrapClientConn(1, nil, &net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 80}, c)
	if result != c {
		t.Error("expected original conn when src is nil")
	}
}

func TestWrapClientConn_NilDst(t *testing.T) {
	c := &testConn{}
	result := WrapClientConn(1, &net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 80}, nil, c)
	if result != c {
		t.Error("expected original conn when dst is nil")
	}
}

func Test_convertAddr(t *testing.T) {
	// nil addr
	if addr := convertAddr(nil); addr != nil {
		t.Errorf("expected nil, got %v", addr)
	}

	// TCP addr with valid IP
	tcpAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	result := convertAddr(tcpAddr)
	tcpResult, ok := result.(*net.TCPAddr)
	if !ok {
		t.Errorf("expected *net.TCPAddr, got %T", result)
	} else {
		if !tcpResult.IP.Equal(net.IPv4(192, 168, 1, 1)) || tcpResult.Port != 8080 {
			t.Errorf("got %v, want 192.168.1.1:8080", result)
		}
	}

	// UDP addr
	udpAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53}
	result = convertAddr(udpAddr)
	udpResult, ok := result.(*net.UDPAddr)
	if !ok {
		t.Errorf("expected *net.UDPAddr, got %T", result)
	} else {
		if !udpResult.IP.Equal(net.IPv4(10, 0, 0, 1)) || udpResult.Port != 53 {
			t.Errorf("got %v, want 10.0.0.1:53", result)
		}
	}

	// addr with IPv6 zero (unspecified)
	ip6zero := &net.TCPAddr{IP: net.IPv6zero, Port: 9999}
	result = convertAddr(ip6zero)
	tcpResult2, ok := result.(*net.TCPAddr)
	if !ok {
		t.Errorf("expected *net.TCPAddr, got %T", result)
	} else if !tcpResult2.IP.Equal(net.IPv4zero) {
		t.Errorf("expected IPv4zero, got %v", tcpResult2.IP)
	}

	// addr with nil IP
	nilIP := &net.TCPAddr{IP: nil, Port: 1234}
	result = convertAddr(nilIP)
	tcpResult3, ok := result.(*net.TCPAddr)
	if !ok {
		t.Errorf("expected *net.TCPAddr, got %T", result)
	} else if !tcpResult3.IP.Equal(net.IPv4zero) {
		t.Errorf("expected IPv4zero for nil IP, got %v", tcpResult3.IP)
	}
}

func Test_serverConn_RemoteAddr_LocalAddr(t *testing.T) {
	conn := &testConn{}
	sc := &serverConn{Conn: conn}
	if sc.RemoteAddr().String() != "1.2.3.4:1234" {
		t.Errorf("unexpected RemoteAddr: %s", sc.RemoteAddr())
	}
	if sc.LocalAddr().String() != "5.6.7.8:5678" {
		t.Errorf("unexpected LocalAddr: %s", sc.LocalAddr())
	}
}

func Test_serverConn_RemoteAddr_LocalAddr_WithProxyproto(t *testing.T) {
	// When the inner conn is a proxyproto.Conn
	rawConn := &testConn{}
	ppConn := proxyproto.NewConn(rawConn)
	sc := &serverConn{Conn: ppConn}
	if sc.RemoteAddr().String() != "1.2.3.4:1234" {
		t.Errorf("unexpected RemoteAddr: %s", sc.RemoteAddr())
	}
	if sc.LocalAddr().String() != "5.6.7.8:5678" {
		t.Errorf("unexpected LocalAddr: %s", sc.LocalAddr())
	}
}

func Test_serverConn_CloseRead(t *testing.T) {
	conn := &testConn{}
	sc := &serverConn{Conn: conn}
	err := sc.CloseRead()
	if err != xio.ErrUnsupported {
		t.Errorf("expected ErrUnsupported, got %v", err)
	}
}

func Test_serverConn_CloseWrite(t *testing.T) {
	conn := &testConn{}
	sc := &serverConn{Conn: conn}
	err := sc.CloseWrite()
	if err != xio.ErrUnsupported {
		t.Errorf("expected ErrUnsupported, got %v", err)
	}
}
