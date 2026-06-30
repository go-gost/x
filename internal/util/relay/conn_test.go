package relay

import (
	"net"
	"testing"
)

// pipeConn is a net.Conn backed by bytes.Buffer — Write writes to buf, Read reads from buf.
type pipeConn struct {
	net.Conn
	buf []byte
}

func newPipeConn() *pipeConn {
	return &pipeConn{}
}
func (c *pipeConn) Read(b []byte) (int, error) {
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}
func (c *pipeConn) Write(b []byte) (int, error) {
	c.buf = append(c.buf, b...)
	return len(b), nil
}
func (c *pipeConn) Close() error { return nil }

func Test_udpTunConn_domainRoundTrip(t *testing.T) {
	pc1 := newPipeConn()
	server := UDPTunServerConn(pc1)

	domain := &domainAddr{network: "udp", host: "dns.google", port: 53}
	_, err := server.WriteTo([]byte("hello"), domain)
	if err != nil {
		t.Fatal(err)
	}

	pc2 := newPipeConn()
	pc2.Write(pc1.buf)

	_, addr, err := UDPTunServerConn(pc2).ReadFrom(make([]byte, 1500))
	if err != nil {
		t.Fatal(err)
	}

	da, ok := addr.(*domainAddr)
	if !ok {
		t.Fatalf("expected *domainAddr, got %T: %s", addr, addr)
	}
	if da.host != "dns.google" || da.port != 53 {
		t.Fatalf("expected dns.google:53, got %s:%d", da.host, da.port)
	}
}

func Test_udpTunConn_ipRoundTrip(t *testing.T) {
	pc1 := newPipeConn()
	server := UDPTunServerConn(pc1)

	ipAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}
	_, err := server.WriteTo([]byte("hello"), ipAddr)
	if err != nil {
		t.Fatal(err)
	}

	pc2 := newPipeConn()
	pc2.Write(pc1.buf)

	_, addr, err := UDPTunServerConn(pc2).ReadFrom(make([]byte, 1500))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := addr.(*net.UDPAddr); !ok {
		t.Fatalf("expected *net.UDPAddr, got %T: %s", addr, addr)
	}
}
