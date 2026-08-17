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
	conn := newUDPAssociationConn(ctx, &net.UDPAddr{}, 0, dial, nil, nil)
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
		0,
		func(context.Context, net.Addr) (net.PacketConn, error) { return upstream, nil },
		func() error {
			idleClosed++
			return nil
		},
		nil,
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

func TestUDPAssociationConnTunnelFailureIsIsolated(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []*fakePacketConn
	)
	conn := newUDPAssociationConn(
		context.Background(),
		&net.UDPAddr{},
		0,
		func(context.Context, net.Addr) (net.PacketConn, error) {
			pc := newFakePacketConn()
			mu.Lock()
			calls = append(calls, pc)
			mu.Unlock()
			return pc, nil
		},
		nil,
		nil,
	)
	t.Cleanup(func() { conn.Close() })

	addr1 := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	addr2 := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 443}
	if _, err := conn.WriteTo([]byte("first"), addr1); err != nil {
		t.Fatalf("first WriteTo failed: %v", err)
	}
	if _, err := conn.WriteTo([]byte("second"), addr2); err != nil {
		t.Fatalf("second WriteTo failed: %v", err)
	}

	mu.Lock()
	first, second := calls[0], calls[1]
	mu.Unlock()
	first.queueReadError(errors.New("stream reset"))
	select {
	case <-first.closed:
	case <-time.After(time.Second):
		t.Fatal("failed tunnel was not removed")
	}

	second.queueRead([]byte("reply"), addr2)
	buf := make([]byte, 32)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("healthy tunnel failed after peer reset: %v", err)
	}
	if string(buf[:n]) != "reply" || addr.String() != addr2.String() {
		t.Fatalf("unexpected healthy tunnel reply %q from %v", buf[:n], addr)
	}

	if _, err := conn.WriteTo([]byte("retry"), addr1); err != nil {
		t.Fatalf("retry WriteTo failed: %v", err)
	}
	mu.Lock()
	callCount := len(calls)
	mu.Unlock()
	if callCount != 3 {
		t.Fatalf("expected failed destination to redial, got %d dials", callCount)
	}
}

func TestUDPAssociationConnDialTimeout(t *testing.T) {
	dialErr := make(chan error, 1)
	conn := newUDPAssociationConn(
		context.Background(),
		&net.UDPAddr{},
		20*time.Millisecond,
		func(ctx context.Context, _ net.Addr) (net.PacketConn, error) {
			<-ctx.Done()
			dialErr <- ctx.Err()
			return nil, ctx.Err()
		},
		nil,
		nil,
	)
	t.Cleanup(func() { conn.Close() })

	payload := []byte("request")
	n, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443})
	if err != nil || n != len(payload) {
		t.Fatalf("timed out datagram was not dropped cleanly: n=%d err=%v", n, err)
	}
	if err := <-dialErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected dial deadline, got %v", err)
	}
}

func TestUDPAssociationConnDialDoesNotHoldAssociationLock(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	conn := newUDPAssociationConn(
		context.Background(),
		&net.UDPAddr{},
		0,
		func(context.Context, net.Addr) (net.PacketConn, error) {
			close(started)
			<-release
			return newFakePacketConn(), nil
		},
		nil,
		nil,
	)
	t.Cleanup(func() { conn.Close() })

	writeDone := make(chan struct{})
	go func() {
		conn.WriteTo([]byte("request"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443})
		close(writeDone)
	}()
	<-started

	deadlineDone := make(chan error, 1)
	go func() {
		deadlineDone <- conn.SetReadDeadline(time.Now().Add(time.Second))
	}()
	select {
	case err := <-deadlineDone:
		if err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial held the association lock")
	}

	close(release)
	<-writeDone
}

type fakePacket struct {
	data []byte
	addr net.Addr
	err  error
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

func (c *fakePacketConn) queueReadError(err error) {
	c.reads <- fakePacket{err: err}
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
		if packet.err != nil {
			return 0, nil, packet.err
		}
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
