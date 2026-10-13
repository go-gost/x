package tun

import (
	"context"
	"net"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
)

// zeroLengthThenPacket is a tun device that hands the reader one empty packet
// before a real one. An Android VpnService fd does exactly that, and the read
// is legal: zero bytes, no error.
//
// This is the shape of the crash that took the spoke down on 2026-10-12. The
// last line the phone logged was a dial inside this relay path
// ("connect /ip", forward/connector.go:44) and crash.log held only
// "panic: runtime error: index out of range [0] with length 0" — because
// waterutil.IsIPv4/IsIPv6 index packet[0] with no length check, so classifying
// an empty read panicked right there. sourceOf/destinationOf (p2p.go) already
// guard the empty buffer; these read loops never did.
type zeroLengthThenPacket struct {
	empties int
	packet  []byte
	sent    bool
}

func (d *zeroLengthThenPacket) Read(p []byte) (int, error) {
	if d.empties > 0 {
		d.empties--
		return 0, nil
	}
	if !d.sent && len(d.packet) > 0 {
		d.sent = true
		return copy(p, d.packet), nil
	}
	return 0, net.ErrClosed
}

func (d *zeroLengthThenPacket) Write(p []byte) (int, error) { return len(p), nil }

// TestTransportClientSurvivesAnEmptyPacketRead: the relay loop must drop a
// zero-length read and carry on — the packet that follows it still reaches the
// link — instead of panicking inside waterutil on packet[0].
func TestTransportClientSurvivesAnEmptyPacketRead(t *testing.T) {
	h := newTestHandler(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dev := &zeroLengthThenPacket{empties: 1, packet: realIPv4Packet()}
	ccA, ccB := net.Pipe()
	defer ccA.Close()
	defer ccB.Close()

	// Whatever the relay writes to the link, collected here: the proof that the
	// loop was still running after the empty read.
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		ccB.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := ccB.Read(buf)
		if err != nil && n <= 0 {
			got <- nil
			return
		}
		got <- append([]byte{}, buf[:n]...)
	}()

	panicked := make(chan any, 1)
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked <- r
			}
		}()
		errCh <- h.transportClient(ctx, dev, ccA, xlogger.Nop())
	}()

	select {
	case r := <-panicked:
		t.Fatalf("transportClient panicked on an empty packet read: %v", r)
	case pkt := <-got:
		if len(pkt) == 0 {
			t.Fatal("nothing reached the link: the loop died with the empty read")
		}
	case err := <-errCh:
		t.Fatalf("transportClient returned (%v) instead of forwarding the packet after the empty read", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the relay to forward the packet")
	}
}
