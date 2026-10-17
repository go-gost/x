package tun

import (
	"bytes"
	"context"
	"io"
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

// nudgeDevice is a device whose reader the test wakes on demand: Read blocks
// until fed. The transport's device reader is not context-aware, so a test
// that ends the link feeds it once to let the transport unwind — the same
// wait collectFirstError documents.
type nudgeDevice struct{ ch chan []byte }

func (d *nudgeDevice) Read(p []byte) (int, error) {
	b, ok := <-d.ch
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (d *nudgeDevice) Write(p []byte) (int, error) { return len(p), nil }

func (d *nudgeDevice) Close() error                     { return nil }
func (d *nudgeDevice) LocalAddr() net.Addr              { return nil }
func (d *nudgeDevice) RemoteAddr() net.Addr             { return nil }
func (d *nudgeDevice) SetDeadline(time.Time) error      { return nil }
func (d *nudgeDevice) SetReadDeadline(time.Time) error  { return nil }
func (d *nudgeDevice) SetWriteDeadline(time.Time) error { return nil }

// A hub side that rebuilt its session under this dial stops echoing the
// registration: on this side the stream is a zombie. Nothing closes the dial,
// and once the first echo cleared the one-shot no read deadline is left, so
// before the watchdog the spoke stayed mute forever — 2026-10-17, 17 minutes
// of blackhole with both ends reporting the path up, healed only by a manual
// entrypoint restart. Silence after the first echo must end the dial, so the
// caller redials and re-registers: that re-dial is what heals a hub-side
// rebuild (observed as `peer relay session up … gen=43 client=true`).
func TestP2PDialRedialsWhenEchoesStop(t *testing.T) {
	oldReg := p2pRegisterInterval
	p2pRegisterInterval = 20 * time.Millisecond
	defer func() { p2pRegisterInterval = oldReg }()

	oldInbound := p2pInboundTimeout
	p2pInboundTimeout = 150 * time.Millisecond
	defer func() { p2pInboundTimeout = oldInbound }()

	peers := make(chan net.Conn, 4)
	router := &fakeRouter{dialFunc: func(context.Context, string, string) (net.Conn, error) {
		local, peer := net.Pipe()
		peers <- peer
		return local, nil
	}}

	device := &nudgeDevice{ch: make(chan []byte, 4)}
	// Closing the device wakes its reader with EOF, which is how the dial
	// loop unwinds (ErrTun) and this test leaves no dialing goroutine behind.
	defer close(device.ch)

	h := newTestHandler(nil, router)
	h.md.passphrase = testPassphrase

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = h.handleClient(ctx, device, "ip", testPeerKey, testConfig(), xlogger.Nop())
	}()

	var peer1 net.Conn
	select {
	case peer1 = <-peers:
	case <-time.After(2 * time.Second):
		t.Fatal("no dial")
	}
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, peer1)
		close(drained)
	}()

	// One echo proves the link alive; the hub then goes silent.
	if _, err := peer1.Write(bareEcho()); err != nil {
		t.Fatal(err)
	}
	// Past the silence window, wake the device reader so the transport can
	// unwind once its read deadline has already fired.
	time.Sleep(3 * p2pInboundTimeout)
	device.ch <- realIPv4Packet()

	select {
	case <-peers:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not end (and redial) after the hub stopped answering")
	}
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("the silent dial was not closed")
	}
}
