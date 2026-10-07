package tun

import (
	"context"
	"testing"

	listenertun "github.com/go-gost/x/listener/tun"
)

// oversizeDevice rejects every write the way a real tun device rejects a
// packet bigger than its buffers.
type oversizeDevice struct{ nopDevice }

func (oversizeDevice) Write([]byte) (int, error) {
	return 0, listenertun.ErrPacketTooLarge
}

// An oversized datagram is dropped and counted, but the peer's stream
// survives: killing the stream over one undeliverable packet turns a
// sender-side anomaly into a reconnect storm.
func TestP2POversizedDatagramKeepsStream(t *testing.T) {
	var warns []string
	hub := newP2PHub(oversizeDevice{}, newTestRouter(), nil,
		func(s string) { warns = append(warns, s) })
	_, peerEnd := newDatagramPipe(4)
	s := newPeerStream(context.Background(), "peer-a", peerEnd)

	pkt := make([]byte, 20546)
	for i := 0; i < 2; i++ {
		if err := hub.fromSpoke(s, pkt); err != nil {
			t.Fatalf("fromSpoke #%d: %v, want nil (drop, don't kill the stream)", i, err)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %d, want 1 (first miss now, flood summarized per window)", len(warns))
	}
}
