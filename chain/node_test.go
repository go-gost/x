package chain

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"

	xlogger "github.com/go-gost/x/logger"
)

// testTransport implements chain.Transporter with real TCP dials.
type testTransport struct {
	dialer  *net.Dialer
	options chain.TransportOptions
}

func (t *testTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.dialer.DialContext(ctx, "tcp", addr)
}

func (t *testTransport) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (t *testTransport) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (t *testTransport) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	return nil, errors.New("not implemented")
}

func (t *testTransport) Multiplex() bool { return false }

func (t *testTransport) Options() *chain.TransportOptions { return &t.options }

func (t *testTransport) Copy() chain.Transporter { return t }

func TestNodeProbeTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// accept one connection, then close immediately (TCP probe only needs dial+handshake)
	go func() {
		for {
			conn, _ := l.Accept()
			if conn != nil {
				conn.Close()
			}
		}
	}()

	addr := l.Addr().String()
	tr := &testTransport{dialer: &net.Dialer{Timeout: 2 * time.Second}}
	node := chain.NewNode("test", addr, chain.TransportNodeOption(tr))

	cfg := &chain.ProbeConfig{
		Type:     chain.ProbeTypeTCP,
		Addr:     addr,
		Interval: 100 * time.Millisecond,
		Timeout:  2 * time.Second,
	}

	StartNodeProbe(node, cfg, xlogger.Nop())

	// Wait for first probe
	time.Sleep(300 * time.Millisecond)

	pr := node.ProbeResult()
	if pr == nil || !pr.Success {
		t.Fatalf("expected successful probe, got %+v", pr)
	}

	// Close listener → next probe fails
	l.Close()
	time.Sleep(300 * time.Millisecond)

	pr = node.ProbeResult()
	if pr == nil || pr.Success {
		t.Fatalf("expected failed probe after listener close, got %+v", pr)
	}
	if node.Marker().Count() == 0 {
		t.Error("expected marker count > 0 after failure")
	}

	node.Close()
}

func TestNodeProbeClose(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, _ := l.Accept()
			if conn != nil {
				conn.Close()
			}
		}
	}()

	addr := l.Addr().String()
	tr := &testTransport{dialer: &net.Dialer{Timeout: 2 * time.Second}}
	node := chain.NewNode("test", addr, chain.TransportNodeOption(tr))

	cfg := &chain.ProbeConfig{
		Type:     chain.ProbeTypeTCP,
		Addr:     addr,
		Interval: 100 * time.Millisecond,
		Timeout:  2 * time.Second,
	}

	StartNodeProbe(node, cfg, xlogger.Nop())
	time.Sleep(150 * time.Millisecond)

	// Snapshot result before close
	lastSuccess := node.ProbeResult().Success
	if !lastSuccess {
		t.Fatal("expected initial success before close")
	}

	node.Close()

	// Capture marker count right after close
	countAfterClose := node.Marker().Count()

	// Wait longer than probe interval — no more updates after close
	time.Sleep(300 * time.Millisecond)

	// Marker count should not increase after close (no more probes running)
	if node.Marker().Count() != countAfterClose {
		t.Errorf("marker changed after close: was %d, now %d", countAfterClose, node.Marker().Count())
	}
}

func TestNodeProbeDisabled(t *testing.T) {
	node := chain.NewNode("no-probe", "addr")
	// nil config → no-op
	StartNodeProbe(node, nil, xlogger.Nop())
	if pr := node.ProbeResult(); pr != nil {
		t.Error("expected nil probe result for disabled probe")
	}
	// empty addr → no-op
	StartNodeProbe(node, &chain.ProbeConfig{}, xlogger.Nop())
	if pr := node.ProbeResult(); pr != nil {
		t.Error("expected nil probe result for empty addr")
	}
}

func TestNodeProbeCmd(t *testing.T) {
	// Cmd probe doesn't need a transport — StartNodeProbe skips the addr check.
	node := chain.NewNode("cmd-test", "")
	cfg := &chain.ProbeConfig{
		Type:     chain.ProbeTypeCmd,
		Command:  "true",
		Interval: 100 * time.Millisecond,
		Timeout:  2 * time.Second,
	}

	StartNodeProbe(node, cfg, xlogger.Nop())
	time.Sleep(300 * time.Millisecond)

	pr := node.ProbeResult()
	if pr == nil || !pr.Success {
		t.Fatalf("expected cmd probe success, got %+v", pr)
	}
	if node.Marker().Count() != 0 {
		t.Errorf("expected marker count 0 after success, got %d", node.Marker().Count())
	}

	// Switch to failing command
	cfg2 := &chain.ProbeConfig{
		Type:     chain.ProbeTypeCmd,
		Command:  "false",
		Interval: 100 * time.Millisecond,
		Timeout:  2 * time.Second,
	}
	node.Close() // stop old probe
	node2 := chain.NewNode("cmd-test-2", "")
	StartNodeProbe(node2, cfg2, xlogger.Nop())
	time.Sleep(300 * time.Millisecond)

	pr2 := node2.ProbeResult()
	if pr2 == nil || pr2.Success {
		t.Fatalf("expected cmd probe failure for exit 1, got %+v", pr2)
	}
	if node2.Marker().Count() == 0 {
		t.Error("expected marker count > 0 after cmd failure")
	}

	node2.Close()
}

func TestNodeProbeCmdDisabled(t *testing.T) {
	// cmd probe without command → no-op
	node := chain.NewNode("cmd-disabled", "")
	cfg := &chain.ProbeConfig{
		Type:    chain.ProbeTypeCmd,
		Command: "",
	}
	StartNodeProbe(node, cfg, xlogger.Nop())
	if pr := node.ProbeResult(); pr != nil {
		t.Error("expected nil probe result for empty command")
	}
}

func TestNodeProbeHTTP(t *testing.T) {
	// Start a small HTTP server
	mux := &httpTestMux{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go mux.serve(conn)
		}
	}()

	addr := l.Addr().String()
	tr := &testTransport{dialer: &net.Dialer{Timeout: 2 * time.Second}}
	node := chain.NewNode("test-http", addr, chain.TransportNodeOption(tr))

	cfg := &chain.ProbeConfig{
		Type:           chain.ProbeTypeHTTP,
		Addr:           addr,
		Interval:       100 * time.Millisecond,
		Timeout:        2 * time.Second,
		HTTPPath:       "/health",
		ExpectedStatus: 200,
	}

	// Case 1: server returns 200
	mux.status.Store(200)
	StartNodeProbe(node, cfg, xlogger.Nop())
	time.Sleep(300 * time.Millisecond)

	pr := node.ProbeResult()
	if pr == nil || !pr.Success {
		t.Fatalf("expected HTTP 200 probe success, got %+v", pr)
	}

	// Case 2: server returns 500
	mux.status.Store(500)
	time.Sleep(300 * time.Millisecond)

	pr = node.ProbeResult()
	if pr == nil || pr.Success {
		t.Fatalf("expected HTTP 500 probe failure, got %+v", pr)
	}

	node.Close()
}

// httpTestMux is a minimal HTTP server that returns a configurable status.
type httpTestMux struct {
	status atomic.Int32
}

func (m *httpTestMux) serve(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	// Parse just enough to construct a response
	body := "HTTP/1.1 000 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	switch m.status.Load() {
	case 200:
		body = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	case 500:
		body = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	}
	_ = n
	conn.Write([]byte(body))
}
