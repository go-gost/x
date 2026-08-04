package masque

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestUDPAssociationConnRoutesByDestination(t *testing.T) {
	type dialCall struct {
		addr net.Addr
		conn *fakePacketConn
	}

	var (
		mu    sync.Mutex
		calls []dialCall
	)
	dial := func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
		conn := newFakePacketConn()
		mu.Lock()
		calls = append(calls, dialCall{addr: addr, conn: conn})
		mu.Unlock()
		return conn, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := newUDPAssociationConn(ctx, &net.UDPAddr{}, dial, nil)
	cancel() // The route dial context ends before the UDP association is used.
	t.Cleanup(func() { conn.Close() })

	addr1 := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}
	addr2 := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	if _, err := conn.WriteTo([]byte("first"), addr1); err != nil {
		t.Fatalf("first WriteTo failed: %v", err)
	}
	if _, err := conn.WriteTo([]byte("second"), addr1); err != nil {
		t.Fatalf("second WriteTo failed: %v", err)
	}
	if _, err := conn.WriteTo([]byte("third"), addr2); err != nil {
		t.Fatalf("third WriteTo failed: %v", err)
	}

	mu.Lock()
	gotCalls := append([]dialCall(nil), calls...)
	mu.Unlock()
	if len(gotCalls) != 2 {
		t.Fatalf("expected one tunnel per destination, got %d", len(gotCalls))
	}
	if gotCalls[0].addr.String() != addr1.String() || gotCalls[1].addr.String() != addr2.String() {
		t.Fatalf("unexpected tunnel destinations: %s, %s", gotCalls[0].addr, gotCalls[1].addr)
	}
	if got := gotCalls[0].conn.writtenData(); len(got) != 2 || string(got[0]) != "first" || string(got[1]) != "second" {
		t.Fatalf("unexpected writes for first destination: %q", got)
	}
	if got := gotCalls[1].conn.writtenData(); len(got) != 1 || string(got[0]) != "third" {
		t.Fatalf("unexpected writes for second destination: %q", got)
	}

	replyAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	gotCalls[1].conn.queueRead([]byte("reply"), replyAddr)
	buf := make([]byte, 32)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("unexpected reply: %q", buf[:n])
	}
	if addr.String() != replyAddr.String() {
		t.Fatalf("expected reply from %s, got %s", replyAddr, addr)
	}
}

func TestUDPAssociationConnClose(t *testing.T) {
	upstream := newFakePacketConn()
	idleClosed := 0
	conn := newUDPAssociationConn(
		context.Background(),
		&net.UDPAddr{},
		func(context.Context, net.Addr) (net.PacketConn, error) { return upstream, nil },
		func() error {
			idleClosed++
			return nil
		},
	)

	if _, err := conn.WriteTo([]byte("request"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if idleClosed != 1 {
		t.Fatalf("expected idle stream to be closed once, got %d", idleClosed)
	}
	if !upstream.isClosed() {
		t.Fatal("expected destination tunnel to be closed")
	}
	if _, err := conn.WriteTo([]byte("request"), &net.UDPAddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

type fakePacket struct {
	data []byte
	addr net.Addr
}

type fakePacketConn struct {
	reads     chan fakePacket
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	writes    [][]byte
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		reads:  make(chan fakePacket, 1),
		closed: make(chan struct{}),
	}
}

func (c *fakePacketConn) queueRead(data []byte, addr net.Addr) {
	c.reads <- fakePacket{data: append([]byte(nil), data...), addr: addr}
}

func (c *fakePacketConn) writtenData() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][]byte, len(c.writes))
	for i, data := range c.writes {
		result[i] = append([]byte(nil), data...)
	}
	return result
}

func (c *fakePacketConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.reads:
		return copy(b, packet.data), packet.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	c.mu.Unlock()
	return len(b), nil
}

func (c *fakePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
