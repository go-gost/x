package tun

import (
	"context"
	"net"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
)

// recordDevice remembers what the hub handed to the device, so a test can
// assert a frame never reached it.
type recordDevice struct {
	nopDevice
	wrote [][]byte
}

func (d *recordDevice) Write(p []byte) (int, error) {
	d.wrote = append(d.wrote, append([]byte(nil), p...))
	return len(p), nil
}

// A frame that is not a parseable IPv4 or IPv6 packet is one the kernel will
// refuse with EINVAL — measured, not assumed: on a real up tun device the
// version nibble is the only thing it checks, and anything other than 4 or 6
// comes back EINVAL at any length. Handing one to the device is what killed
// the hub, because that error propagates out of fromSpoke and tears down the
// peer's whole stream. So the frame is dropped and counted instead, exactly
// as an oversized one already is.
func TestP2PNonIPDatagramKeepsStream(t *testing.T) {
	garbage := func(n int, first byte) []byte {
		p := make([]byte, n)
		for i := range p {
			p[i] = 0xFF
		}
		p[0] = first
		return p
	}

	tests := []struct {
		name string
		pkt  []byte
	}{
		{"version 5", garbage(60, 0x55)},
		{"version 7", garbage(60, 0x75)},
		{"all zeroes", garbage(60, 0x00)},
		{"empty", []byte{}},
		{"oversized and non-IP", garbage(20530, 0x55)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev := &recordDevice{}
			var warns []string
			hub := newP2PHub(dev, newTestRouter(), nil,
				func(s string) { warns = append(warns, s) })
			_, peerEnd := newDatagramPipe(4)
			s := newPeerStream(context.Background(), "peer-a", peerEnd)

			if err := hub.fromSpoke(s, tc.pkt); err != nil {
				t.Fatalf("fromSpoke: %v, want nil (drop, don't kill the stream)", err)
			}
			if len(dev.wrote) != 0 {
				t.Fatalf("device got %d writes, want 0", len(dev.wrote))
			}
			if len(warns) != 1 {
				t.Fatalf("warnings = %d, want 1 (a dropped frame must stay visible)", len(warns))
			}

			// The guard must not have cost the peer its link: the next
			// well-formed packet still has to reach the device.
			good := udpPacket("10.0.0.1", "10.0.0.9", 1, 3)
			if err := hub.fromSpoke(s, good); err != nil {
				t.Fatalf("fromSpoke (valid packet after a bad one): %v", err)
			}
			if len(dev.wrote) != 1 {
				t.Fatalf("device got %d writes, want 1", len(dev.wrote))
			}
		})
	}
}

// The spoke's downlink is the same hazard and already carries this guard —
// which is why the phone logs "unknown packet, discarded" all day and never
// dies, while the hub has no equivalent. This pins that asymmetry: if the
// spoke's check is ever dropped, the device must still receive nothing, and
// the run must end on the deadline rather than on an EINVAL from the kernel.
func TestTransportClientDropsNonIPFrames(t *testing.T) {
	device, kernelSide := net.Pipe()
	ccA, ccB := net.Pipe()
	defer device.Close()
	defer ccA.Close()

	h := newTestHandler(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceGot := make(chan []byte, 1)
	go func() {
		var acc []byte
		buf := make([]byte, 64)
		kernelSide.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		for {
			n, err := kernelSide.Read(buf[:])
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		deviceGot <- acc
	}()

	errCh := make(chan error, 1)
	go func() { errCh <- h.transportClient(ctx, device, ccA, xlogger.Nop()) }()

	bad := make([]byte, 60)
	for i := range bad {
		bad[i] = 0x55 // version 5: not IPv4, not IPv6
	}
	if _, err := ccB.Write(bad); err != nil {
		t.Fatal(err)
	}
	// A well-formed packet behind it must still arrive: if the guard dropped
	// the link instead of the frame, this never lands.
	good := realIPv4Packet()
	if _, err := ccB.Write(good); err != nil {
		t.Fatal(err)
	}

	got := <-deviceGot
	if len(got) != len(good) {
		t.Fatalf("device received %d bytes, want %d (only the well-formed packet)", len(got), len(good))
	}
}
