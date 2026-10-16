package tun

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	tun_util "github.com/go-gost/x/internal/util/tun"
	xlogger "github.com/go-gost/x/logger"
)

const testPassphrase = "0123456789abcdef"

// testPeerKey is what a p2p dial target looks like: a bare peer key, not an
// address, which is also why the client takes its network as "ip".
const testPeerKey = "zRiIjY4aXiq4Az2938w3blPXE07vbdFeQ2jwWVxn6Vk"

func testConfig() *tun_util.Config {
	return &tun_util.Config{Net: []net.IPNet{{
		IP:   net.IPv4(10, 100, 100, 250),
		Mask: net.CIDRMask(24, 32),
	}}}
}

// countHandshakes reads registration handshake frames off the far end of the
// dial until limit of them arrive or the window ends.
func countHandshakes(t *testing.T, c net.Conn, window time.Duration, limit int) int {
	t.Helper()

	want := keepAliveHeaderLength + net.IPv6len
	n := 0
	deadline := time.Now().Add(window)
	for n < limit && time.Now().Before(deadline) {
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

		buf := make([]byte, 2*want)
		got, err := c.Read(buf)
		if err != nil {
			continue // a quiet moment, not the end of the window
		}
		if got != want || !bytes.Equal(buf[:4], magicHeader) {
			t.Fatalf("unexpected frame on the dial (%d bytes)", got)
		}
		n++
	}
	return n
}

// A p2p dial's stream survives the peer session under it being rebuilt, so the
// far side's route to this device can be reclaimed while the dial still reads
// as alive. The registration handshake is the only thing that restores it, so
// it has to repeat on a p2p dial even with no keepalive period configured.
func TestP2PDialRefreshesRegistration(t *testing.T) {
	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()

	link, peer := net.Pipe()
	defer link.Close()
	defer peer.Close()

	h := newTestHandler(nil, &fakeRouter{dialConn: link})
	h.md.passphrase = testPassphrase

	old := p2pRegisterInterval
	p2pRegisterInterval = 20 * time.Millisecond
	defer func() { p2pRegisterInterval = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = h.handleClient(ctx, device, "ip", testPeerKey, testConfig(), xlogger.Nop())
	}()

	// One handshake at dial time and the rest from the refresh: three in a
	// second only fits if the registration repeats.
	if got := countHandshakes(t, peer, time.Second, 3); got < 3 {
		t.Fatalf("p2p dial sent %d registration handshake(s) in 1s, want >= 3", got)
	}
}

// A socket dial needs no repeat: the transport itself reports the far side
// gone. The p2p refresh must not leak into that shape.
func TestSocketDialSendsRegistrationOnce(t *testing.T) {
	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()

	link, peer := net.Pipe()
	defer link.Close()
	defer peer.Close()

	h := newTestHandler(nil, &fakeRouter{dialConn: link})
	h.md.passphrase = testPassphrase

	old := p2pRegisterInterval
	p2pRegisterInterval = 20 * time.Millisecond
	defer func() { p2pRegisterInterval = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = h.handleClient(ctx, device, "udp", "192.168.100.100:8421", testConfig(), xlogger.Nop())
	}()

	if got := countHandshakes(t, peer, 300*time.Millisecond, 2); got != 1 {
		t.Fatalf("socket dial sent %d registration handshake(s), want 1", got)
	}
}
