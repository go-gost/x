package tun

import "testing"

// TestPacketFamilyGuardsTheEmptyBuffer pins the guard every packet classifier
// in this repo must carry. waterutil.IsIPv4/IsIPv6 index packet[0] with no
// length check, so an empty buffer — a device's legal zero-byte read — panics
// with "index out of range [0] with length 0": the panic that took the spoke
// down on 2026-10-12, in a c-shared library where nothing could catch it.
func TestPacketFamilyGuardsTheEmptyBuffer(t *testing.T) {
	if IPv4Packet(nil) || IPv4Packet([]byte{}) {
		t.Error("an empty buffer is not an IPv4 packet")
	}
	if IPv6Packet(nil) || IPv6Packet([]byte{}) {
		t.Error("an empty buffer is not an IPv6 packet")
	}

	// The guard must not reject the packets it reports on: a zero-length buffer
	// is the only case it answers "no" for.
	v4 := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 0, 1}
	if !IPv4Packet(v4) {
		t.Error("a real IPv4 header is not reported as one")
	}
	if IPv6Packet(v4) {
		t.Error("an IPv4 header is reported as IPv6")
	}

	v6 := make([]byte, 40)
	v6[0] = 0x60
	if !IPv6Packet(v6) {
		t.Error("a real IPv6 header is not reported as one")
	}
	if IPv4Packet(v6) {
		t.Error("an IPv6 header is reported as IPv4")
	}
}
