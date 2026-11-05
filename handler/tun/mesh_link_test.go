package tun

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// meshConn is one end of a bidirectional datagram pipe. The link owns one end;
// the test owns the other. Close unblocks Read but does not close the datagram
// queues underneath (a blocked Write on a closed queue would panic); a blocked
// writer falls back to the datagramPipe timeout.
type meshConn struct {
	send, recv *datagramPipe
	done       chan struct{}
	once       sync.Once
}

func newMeshConn(send, recv *datagramPipe) *meshConn {
	return &meshConn{send: send, recv: recv, done: make(chan struct{})}
}
func (c *meshConn) Read(b []byte) (int, error) {
	select {
	case pkt := <-c.recv.queue:
		return copy(b, pkt), nil
	case <-c.done:
		return 0, io.EOF
	}
}
func (c *meshConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	return c.send.Write(b)
}
func (c *meshConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
func (c *meshConn) LocalAddr() net.Addr         { return peerAddr{"mesh", ""} }
func (c *meshConn) RemoteAddr() net.Addr        { return peerAddr{"mesh", "peer"} }
func (c *meshConn) SetDeadline(time.Time) error { return nil }
func (c *meshConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *meshConn) SetWriteDeadline(time.Time) error { return nil }

// newMeshPipe returns the link's end and the test's end. Link writes arrive at
// the test's recv; test writes arrive at the link's recv.
func newMeshPipe() (link, peer *meshConn) {
	toPeer, fromLink := newDatagramPipe(16)
	toLink, fromPeer := newDatagramPipe(16)
	link = newMeshConn(toPeer, fromPeer)
	peer = newMeshConn(toLink, fromLink)
	return
}

func waitReason(t *testing.T, ch <-chan MeshCloseReason) MeshCloseReason {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("link did not close in time")
		return ""
	}
}

func TestMeshLinkWritesEachDatagram(t *testing.T) {
	linkEnd, peer := newMeshPipe()
	reasons := make(chan MeshCloseReason, 1)
	l := newMeshLink("b", linkEnd, true, false, func(_ *meshLink, r MeshCloseReason) {
		select {
		case reasons <- r:
		default:
		}
	})
	l.start(nil, nil, func([]byte) error { return nil })
	t.Cleanup(func() { l.close(MeshCloseShutdown) })

	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 0, 1}
	if !l.enqueue(pkt) {
		t.Fatal("enqueue returned false")
	}
	buf := make([]byte, MaxMessageSize)
	n, err := peer.recv.Read(buf)
	if err != nil {
		t.Fatalf("read peer end: %v", err)
	}
	got := buf[:n]
	if !bytes.Equal(got, pkt) {
		t.Fatalf("wrote %x, want %x", got, pkt)
	}
}

func TestMeshLinkQueueFullDoesNotBlock(t *testing.T) {
	old := meshQueueDepth
	meshQueueDepth = 1
	t.Cleanup(func() { meshQueueDepth = old })

	linkEnd, peer := newMeshPipe()
	l := newMeshLink("b", linkEnd, true, false, nil)
	t.Cleanup(func() { l.close(MeshCloseShutdown) })
	_ = peer

	if !l.enqueue([]byte{1}) {
		t.Fatal("first enqueue returned false")
	}
	start := time.Now()
	if l.enqueue([]byte{2}) {
		t.Fatal("second enqueue returned true with a full queue")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("enqueue blocked for %v", d)
	}
}

func TestMeshLinkRegistrationAndEcho(t *testing.T) {
	linkEnd, peer := newMeshPipe()
	reasons := make(chan MeshCloseReason, 1)
	l := newMeshLink("b", linkEnd, true, false, func(_ *meshLink, r MeshCloseReason) {
		select {
		case reasons <- r:
		default:
		}
	})
	registration := bytes.Repeat([]byte{0x47}, keepAliveHeaderLength)
	l.start(nil, registration, func([]byte) error { return nil })
	t.Cleanup(func() { l.close(MeshCloseShutdown) })

	buf := make([]byte, MaxMessageSize)
	n, err := peer.recv.Read(buf)
	if err != nil {
		t.Fatalf("read registration: %v", err)
	}
	got := buf[:n]
	if !bytes.Equal(got, registration) {
		t.Fatalf("registration = %x, want %x", got, registration)
	}
	if _, err := peer.send.Write(bytes.Repeat([]byte{0x47}, keepAliveHeaderLength)); err != nil {
		t.Fatalf("write echo: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for !l.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatal("link did not become ready after the echo")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if l.lastInbound.Load() == 0 {
		t.Fatal("markInbound did not record the echo")
	}
}

func TestMeshLinkFirstInboundTimeout(t *testing.T) {
	old := meshFirstInboundTimeout
	meshFirstInboundTimeout = 50 * time.Millisecond
	t.Cleanup(func() { meshFirstInboundTimeout = old })

	linkEnd, peer := newMeshPipe()
	reasons := make(chan MeshCloseReason, 1)
	l := newMeshLink("b", linkEnd, true, false, func(_ *meshLink, r MeshCloseReason) {
		select {
		case reasons <- r:
		default:
		}
	})
	l.start(nil, nil, func([]byte) error { return nil })
	t.Cleanup(func() { l.close(MeshCloseShutdown) })
	_ = peer

	if got := waitReason(t, reasons); got != MeshCloseDial {
		t.Fatalf("close reason = %q, want %q", got, MeshCloseDial)
	}
}

func TestMeshLinkIdleDirectLink(t *testing.T) {
	oldFirst, oldInbound, oldIdle := meshFirstInboundTimeout, meshInboundTimeout, meshIdleTimeout
	meshFirstInboundTimeout = time.Second
	meshInboundTimeout = time.Second
	meshIdleTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		meshFirstInboundTimeout, meshInboundTimeout, meshIdleTimeout = oldFirst, oldInbound, oldIdle
	})

	linkEnd, peer := newMeshPipe()
	reasons := make(chan MeshCloseReason, 1)
	l := newMeshLink("b", linkEnd, true, false, func(_ *meshLink, r MeshCloseReason) {
		select {
		case reasons <- r:
		default:
		}
	})
	l.start(nil, nil, func([]byte) error { return nil })
	t.Cleanup(func() { l.close(MeshCloseShutdown) })

	if _, err := peer.send.Write(bytes.Repeat([]byte{0x47}, keepAliveHeaderLength)); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for !l.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatal("link did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := waitReason(t, reasons); got != MeshCloseIdle {
		t.Fatalf("close reason = %q, want %q", got, MeshCloseIdle)
	}
}

func TestMeshLinkCloseIsOnce(t *testing.T) {
	linkEnd, _ := newMeshPipe()
	var calls atomic.Int32
	l := newMeshLink("b", linkEnd, true, false, func(*meshLink, MeshCloseReason) {
		calls.Add(1)
	})
	l.close(MeshCloseRemote)
	l.close(MeshCloseRemote)
	if got := calls.Load(); got != 1 {
		t.Fatalf("onClose calls = %d, want 1", got)
	}
	if l.enqueue([]byte{1}) {
		t.Fatal("enqueue after close returned true")
	}
}
