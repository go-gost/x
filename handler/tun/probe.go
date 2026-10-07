package tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/logger"
)

const (
	// probeMagic tags a device-probe payload so the prober's own socket
	// can tell its looped-back probe apart from anything else.
	probeMagic = "WSPROBE!"
)

var (
	// probeInterval is the ticker between two probe writes.
	probeInterval = 30 * time.Second
	// probeRecvTimeout bounds the wait for the looped-back probe.
	probeRecvTimeout = 5 * time.Second
)

// buildProbePacket assembles a 44-byte IPv4/UDP packet addressed from the
// spoke to itself: 20B IP header + 8B UDP header + 8B magic + 8B seq.
// The UDP checksum is zero, which means "no checksum" on IPv4 and is
// accepted by the kernel; the IP header checksum is computed for real,
// because the kernel silently drops packets with a bad one.
func buildProbePacket(src net.IP, dstPort uint16, seq uint64) []byte {
	ip := src.To4()
	pkt := make([]byte, 44)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], 44)
	// Identification + flags/fragment stay zero: one whole datagram.
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], ip)
	copy(pkt[16:20], ip)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	binary.BigEndian.PutUint16(pkt[20:22], dstPort) // src port: same, harmless
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], 24) // UDP length: header + magic + seq
	// UDP checksum stays zero.
	copy(pkt[28:36], probeMagic)
	binary.BigEndian.PutUint64(pkt[36:44], seq)
	return pkt
}

// probeDevice starts the device-probe loop for one dial iteration when the
// probe switch is on. It returns without starting anything when there is no
// report sink (gost/older callers) or no IPv4 spoke address (IPv6-only).
// runDeviceProbe assumes a non-nil report; this is the single place that
// guarantees it.
func (h *tunHandler) probeDevice(ctx context.Context, dev io.Writer, ips []net.IP) {
	report := h.md.probeReport
	if report == nil {
		return
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			runDeviceProbe(ctx, dev, v4, report, h.options.Logger)
			return
		}
	}
	h.options.Logger.Warnf("device probe: disabled, no IPv4 spoke address")
}

// runDeviceProbe writes a self-addressed UDP probe into dev every tick and
// waits for the kernel to deliver it back to its own bound socket. Every
// write counts as sent (even a failed one — a stalled acked count is itself
// the signal); every looped-back packet with matching magic and seq counts
// as acked. report must be non-nil; the nil guard lives in probeDevice.
//
// The loop ends when ctx ends (per-dial-iteration lifetime, same as
// keepalive). An IPv6-only address disables the probe silently here — the
// caller logs the warn.
func runDeviceProbe(ctx context.Context, dev io.Writer, ip net.IP, report func(sentDelta, ackedDelta uint64), log logger.Logger) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: v4})
	if err != nil {
		log.Warnf("device probe: bind failed: %v", err)
		return
	}
	defer pc.Close()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	var seq uint64
	buf := make([]byte, 64)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		seq++
		if _, err := dev.Write(buildProbePacket(v4, port, seq)); err != nil {
			log.Warnf("device probe: write failed: %v", err)
		}
		report(1, 0)
		_ = pc.SetReadDeadline(time.Now().Add(probeRecvTimeout))
		for {
			n, err := pc.Read(buf)
			if err != nil {
				break // timeout or closed: no ack this round
			}
			if n == 44 && string(buf[28:36]) == probeMagic &&
				binary.BigEndian.Uint64(buf[36:44]) == seq {
				report(0, 1)
				break
			}
		}
	}
}
