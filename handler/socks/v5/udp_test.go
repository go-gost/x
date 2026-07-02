package v5

import (
	"context"
	"net"
	"strconv"
	"testing"

	xnet "github.com/go-gost/x/internal/net"
)

func TestListenPacketInRange(t *testing.T) {
	ctx := context.Background()

	// No range configured: OS picks (port 0), always succeeds.
	lc := &xnet.ListenConfig{}
	cc, err := listenPacketInRange(ctx, lc, "udp", "127.0.0.1", 0, 0)
	if err != nil {
		t.Fatalf("port-0 bind: %v", err)
	}
	cc.Close()

	// Range configured: bound port must fall within [lo, hi]. With 51
	// candidates and attempts = min(span, 64), only a fully-occupied range
	// fails — extremely unlikely on a dev/CI host.
	const lo, hi = 35000, 35050
	cc, err = listenPacketInRange(ctx, lc, "udp", "127.0.0.1", lo, hi)
	if err != nil {
		t.Fatalf("range bind [%d,%d]: %v", lo, hi, err)
	}
	defer cc.Close()

	_, portStr, _ := net.SplitHostPort(cc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	if port < lo || port > hi {
		t.Errorf("bound port %d outside [%d, %d]", port, lo, hi)
	}
}

// A single-port range whose only port is already held must surface the
// EADDRINUSE error (so the caller replies REP 0x01) — no hang, no silent miss.
func TestListenPacketInRange_BusyPort(t *testing.T) {
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blocker bind: %v", err)
	}
	defer blocker.Close()
	_, portStr, _ := net.SplitHostPort(blocker.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)

	lc := &xnet.ListenConfig{}
	if _, err := listenPacketInRange(context.Background(), lc, "udp", "127.0.0.1", port, port); err == nil {
		t.Fatalf("expected bind on held port %d to fail", port)
	}
}
