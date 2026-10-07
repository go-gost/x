package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
)

// a registration handshake frame, as sent by the other side of a tun link
func registrationFrame() []byte {
	frame := make([]byte, 0, keepAliveHeaderLength+net.IPv6len)
	frame = append(frame, magicHeader...)
	frame = append(frame, []byte("0123456789abcdef")...) // passphrase
	frame = append(frame, net.IPv4(10, 20, 0, 2).To16()...)
	return frame
}

func bareEcho() []byte {
	return append(append([]byte{}, magicHeader...), []byte("0123456789abcdef")...)
}

func realIPv4Packet() []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // v4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], 20)
	pkt[9] = 1 // ICMP
	return pkt
}

// In a tun link the far side's registration handshake, and the keepalive
// echo, are protocol chatter: they must be swallowed by the client, never
// forwarded into the local device. Only real IP packets may pass.
func TestTransportClientDropsKeepaliveFrames(t *testing.T) {
	device, kernelSide := net.Pipe()
	ccA, ccB := net.Pipe()

	h := newTestHandler(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer device.Close()
	defer ccA.Close()

	// drain everything the device would receive
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

	// Protocol frames must be swallowed...
	if _, err := ccB.Write(registrationFrame()); err != nil {
		t.Fatal(err)
	}
	if _, err := ccB.Write(bareEcho()); err != nil {
		t.Fatal(err)
	}
	// ...and a real IP packet must still reach the device.
	pkt := realIPv4Packet()
	if _, err := ccB.Write(pkt); err != nil {
		t.Fatal(err)
	}
	ccB.Close()

	got := <-deviceGot
	if !bytes.Equal(got, pkt) {
		t.Fatalf("device got %v bytes %x, want only the IP packet %x", len(got), got, pkt)
	}

	<-errCh // client loop exits on the closed link
}

// Without a keepalive period the client sets no read deadline at all, so a
// hub that never answers — not started, or silently refusing — leaves the
// spoke "running" forever on a link that will never deliver. The transport
// must give up waiting for the first inbound byte so the caller redials and
// re-registers; any inbound byte clears the one-shot.
func TestNoKeepaliveClientTimesOutWaitingForFirstInbound(t *testing.T) {
	old := firstInboundTimeout
	firstInboundTimeout = 200 * time.Millisecond
	defer func() { firstInboundTimeout = old }()

	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()
	ccA, ccB := net.Pipe()
	defer ccB.Close() // the link stays open: silence, not closure, must end it

	h := newTestHandler(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- h.transportClient(ctx, device, ccA, xlogger.Nop()) }()

	select {
	case err := <-errCh:
		var nerr net.Error
		if !errors.As(err, &nerr) || !nerr.Timeout() {
			t.Fatalf("transportClient = %v, want a read timeout", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("transportClient waited forever on a silent link")
	}
	// Note: transportClient itself takes ~5s more to return — collectFirstError
	// waits out the device reader, which blocks on an idle device with no
	// context-aware read. That wait is pre-existing; the timeout above is what
	// proves the silent link no longer waits forever.
}

// The mirror: one inbound byte — even protocol chatter, which never reaches
// the device — proves the link alive and clears the one-shot, so a healthy
// but quiet tunnel is never redialed.
func TestNoKeepaliveClientFirstInboundClearsTimeout(t *testing.T) {
	old := firstInboundTimeout
	firstInboundTimeout = 200 * time.Millisecond
	defer func() { firstInboundTimeout = old }()

	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()
	ccA, ccB := net.Pipe()

	h := newTestHandler(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- h.transportClient(ctx, device, ccA, xlogger.Nop()) }()

	if _, err := ccB.Write(bareEcho()); err != nil {
		t.Fatal(err)
	}

	// Three windows of silence past the one-shot: a cleared deadline stays
	// cleared, and the transport must not report anything.
	time.Sleep(3 * firstInboundTimeout)
	select {
	case err := <-errCh:
		t.Fatalf("transportClient reported %v on a healthy quiet link", err)
	default:
	}

	ccB.Close() // unblock the reader; the test proved what it had to
}
