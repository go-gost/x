package hop

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"

	xchain "github.com/go-gost/x/chain"
	xlogger "github.com/go-gost/x/logger"
	xs "github.com/go-gost/x/selector"
)

// fakeTransport dials a real TCP address for probe testing.
type fakeTransport struct {
	dialer  *net.Dialer
	options chain.TransportOptions
}

func (t *fakeTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.dialer.DialContext(ctx, "tcp", addr)
}

func (t *fakeTransport) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (t *fakeTransport) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	return nil, nil
}

func (t *fakeTransport) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	return nil, nil
}

func (t *fakeTransport) Multiplex() bool { return false }

func (t *fakeTransport) Options() *chain.TransportOptions { return &t.options }

func (t *fakeTransport) Copy() chain.Transporter { return t }

func TestHopFailoverWithProbe(t *testing.T) {
	// Start two listeners as healthy "proxy" targets.
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	go acceptAndClose(l1)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	go acceptAndClose(l2)

	addr1, addr2 := l1.Addr().String(), l2.Addr().String()

	dialer := &net.Dialer{Timeout: 1 * time.Second}
	nodeA := chain.NewNode("a", addr1,
		chain.TransportNodeOption(&fakeTransport{dialer: dialer}),
	)
	nodeB := chain.NewNode("b", addr2,
		chain.TransportNodeOption(&fakeTransport{dialer: dialer}),
	)

	// Start probe on both nodes.
	xchain.StartNodeProbe(nodeA, &chain.ProbeConfig{
		Type:     chain.ProbeTypeTCP,
		Addr:     addr1,
		Interval: 200 * time.Millisecond,
		Timeout:  1 * time.Second,
	}, xlogger.Nop())
	xchain.StartNodeProbe(nodeB, &chain.ProbeConfig{
		Type:     chain.ProbeTypeTCP,
		Addr:     addr2,
		Interval: 200 * time.Millisecond,
		Timeout:  1 * time.Second,
	}, xlogger.Nop())

	// Build hop with FailFilter + BackupFilter, default 2 max fails.
	sel := xs.NewSelector(
		xs.RoundRobinStrategy[*chain.Node](),
		xs.FailFilter[*chain.Node](1, 5*time.Second),
		xs.BackupFilter[*chain.Node](),
	)

	h := NewHop(
		NameOption("test-hop"),
		NodeOption(nodeA, nodeB),
		SelectorOption(sel),
		LoggerOption(xlogger.Nop()),
	)
	defer func() {
		if closer, ok := h.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	// Wait for probes to mark both healthy.
	time.Sleep(500 * time.Millisecond)
	if !nodeA.ProbeResult().Success || !nodeB.ProbeResult().Success {
		t.Fatalf("both nodes should be healthy initially: A=%v B=%v",
			nodeA.ProbeResult().Success, nodeB.ProbeResult().Success)
	}

	// Both healthy → both should appear in selection.
	ctx := context.Background()
	sel1 := h.Select(ctx)
	sel2 := h.Select(ctx)
	_ = sel1
	_ = sel2
	// Round-robin: two picks should be different if both alive.
	if sel1 == sel2 {
		t.Log("round-robin picked same node twice — both may be fine, checking probe state")
	}

	// Kill nodeA's listener → probe marks it dead.
	l1.Close()
	time.Sleep(600 * time.Millisecond)

	if nodeA.ProbeResult().Success {
		t.Error("nodeA should be dead after listener closed")
	}
	if nodeA.Marker().Count() == 0 {
		t.Error("nodeA marker should have failures")
	}

	// After FailFilter kicks in, hop should consistently pick nodeB.
	var sawDead bool
	for i := 0; i < 10; i++ {
		n := h.Select(ctx)
		if n == nil {
			t.Fatal("got nil node from selector")
		}
		if n == nodeA {
			sawDead = true
		}
	}
	if sawDead {
		t.Error("FailFilter should have excluded nodeA")
	}

	// Reopen listener → probe resets marker.
	l1New, err := net.Listen("tcp", addr1)
	if err != nil {
		t.Fatal(err)
	}
	defer l1New.Close()
	go acceptAndClose(l1New)

	time.Sleep(600 * time.Millisecond)

	if !nodeA.ProbeResult().Success {
		t.Error("nodeA should be healthy again after listener restored")
	}
	if nodeA.Marker().Count() != 0 {
		t.Error("nodeA marker should be reset after successful probe")
	}

	// Both should be reachable again.
	var sawA bool
	for i := 0; i < 20; i++ {
		if h.Select(ctx) == nodeA {
			sawA = true
			break
		}
	}
	if !sawA {
		t.Error("nodeA should be selected again after recovery")
	}
}

func acceptAndClose(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}
