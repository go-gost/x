package tun

import (
	"bytes"
	"context"
	"encoding/binary"
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
