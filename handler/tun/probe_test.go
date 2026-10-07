package tun

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
)

// fastProbe overrides the production 30s/5s cadence for tests.
func fastProbe(t *testing.T) {
	t.Helper()
	oldInterval, oldTimeout := probeInterval, probeRecvTimeout
	probeInterval, probeRecvTimeout = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { probeInterval, probeRecvTimeout = oldInterval, oldTimeout })
}

func TestRunDeviceProbeReportsSent(t *testing.T) {
	fastProbe(t)
	device, kernelSide := net.Pipe() // same pattern as client_test.go
	defer device.Close()
	defer kernelSide.Close()
	var sent, acked atomic.Uint64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runDeviceProbe(ctx, device, net.ParseIP("127.0.0.1"),
		func(sd, ad uint64) { sent.Add(sd); acked.Add(ad) }, xlogger.Nop())

	buf := make([]byte, 64)
	if err := kernelSide.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := kernelSide.Read(buf)
	if err != nil {
		t.Fatalf("no probe written: %v", err)
	}
	if n != 44 || string(buf[28:36]) != probeMagic {
		t.Fatalf("not a probe packet: n=%d", n)
	}
	// net.Pipe hands the reader its copy before the writer's Write returns,
	// so report(1,0) can lag the Read: poll.
	deadline := time.Now().Add(5 * time.Second)
	for sent.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if sent.Load() < 1 {
		t.Fatal("sent did not advance")
	}
	if acked.Load() != 0 {
		t.Fatal("acked must stall: the pipe never loops back")
	}
}

func TestRunDeviceProbeDeadDevice(t *testing.T) {
	fastProbe(t)
	device, kernelSide := net.Pipe()
	kernelSide.Close() // writes now fail; alternate trigger: device.Close()
	defer device.Close()
	var sent, acked atomic.Uint64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDeviceProbe(ctx, device, net.ParseIP("127.0.0.1"),
			func(sd, ad uint64) { sent.Add(sd); acked.Add(ad) }, xlogger.Nop())
	}()

	deadline := time.Now().Add(5 * time.Second)
	for sent.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not exit on ctx cancel")
	}
	if sent.Load() < 2 {
		t.Fatalf("sent=%d, want >=2 rounds", sent.Load())
	}
	if acked.Load() != 0 {
		t.Fatalf("acked=%d, want 0 on a dead device", acked.Load())
	}
}

func TestProbeDeviceNilReportStartsNothing(t *testing.T) {
	fastProbe(t)
	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()
	h := &tunHandler{} // probeReport nil
	h.options.Logger = xlogger.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.probeDevice(ctx, device, []net.IP{net.ParseIP("127.0.0.1")})
	}()
	// Several 50ms ticks pass; a running loop would have written by now.
	if err := kernelSide.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := kernelSide.Read(buf); err == nil {
		t.Fatal("probe loop started with nil report")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probeDevice did not return")
	}
}

func TestProbeDeviceV6OnlyReturns(t *testing.T) {
	var sent, acked atomic.Uint64
	h := &tunHandler{}
	h.options.Logger = xlogger.Nop()
	h.md.probeReport = func(sd, ad uint64) { sent.Add(sd); acked.Add(ad) }
	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.probeDevice(context.Background(), device, []net.IP{net.ParseIP("2001:db8::1")})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probeDevice blocked on v6-only addresses")
	}
	if sent.Load() != 0 || acked.Load() != 0 {
		t.Fatal("v6-only must report nothing")
	}
}

func TestRunDeviceProbeAckedOnLoopback(t *testing.T) {
	fastProbe(t)
	device, kernelSide := net.Pipe()
	defer device.Close()
	defer kernelSide.Close()
	var sent, acked atomic.Uint64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runDeviceProbe(ctx, device, net.ParseIP("127.0.0.1"),
		func(sd, ad uint64) { sent.Add(sd); acked.Add(ad) }, xlogger.Nop())

	// Play kernel: read the probe from the fake device and hand it to the
	// prober's socket the way local delivery would.
	buf := make([]byte, 64)
	if err := kernelSide.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := kernelSide.Read(buf)
	if err != nil {
		t.Fatalf("no probe written: %v", err)
	}
	port := binary.BigEndian.Uint16(buf[22:24])
	back, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	if _, err := back.Write(buf[:n]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for acked.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if acked.Load() != 1 {
		t.Fatalf("acked=%d, want 1 after loopback", acked.Load())
	}
}

func TestBuildProbePacket(t *testing.T) {
	src := net.ParseIP("10.10.100.250")
	pkt := buildProbePacket(src, 54321, 7)
	if len(pkt) != 44 {
		t.Fatalf("len=%d", len(pkt))
	}
	if pkt[0] != 0x45 || pkt[9] != 17 {
		t.Fatal("not v4/UDP")
	}
	if !net.IP(pkt[12:16]).Equal(src) || !net.IP(pkt[16:20]).Equal(src) {
		t.Fatal("src/dst must both be the spoke address")
	}
	// IP header checksum self-check.
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	if ^uint16(sum) != 0 {
		t.Fatal("bad IP header checksum")
	}
	// UDP checksum must be zero (means "no checksum" on IPv4).
	if pkt[26] != 0 || pkt[27] != 0 {
		t.Fatal("UDP checksum must be zero")
	}
	// dst port, UDP length, magic, seq.
	if port := int(pkt[22])<<8 | int(pkt[23]); port != 54321 {
		t.Fatalf("dst port=%d", port)
	}
	if ln := int(pkt[24])<<8 | int(pkt[25]); ln != 24 {
		t.Fatalf("UDP length=%d, want 24 (8 header + 8 magic + 8 seq)", ln)
	}
	if string(pkt[28:36]) != probeMagic {
		t.Fatalf("magic=%q", pkt[28:36])
	}
	var seq uint64
	for _, b := range pkt[36:44] {
		seq = seq<<8 | uint64(b)
	}
	if seq != 7 {
		t.Fatalf("seq=%d", seq)
	}
}
