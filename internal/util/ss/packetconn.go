package ss

import (
	"net"
	"sync"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/shadowaead"
)

// AEADPacketConn wraps pc with per-packet salt+AEAD framing (the classic AEAD
// shadowsocks UDP wire format), mirroring the upstream shadowaead.packetConn
// on the fork's stateless Pack/Unpack.
func AEADPacketConn(pc net.PacketConn, ciph core.ShadowCipher) net.PacketConn {
	const maxPacketSize = 64 * 1024
	return &aeadPacketConn{PacketConn: pc, ciph: ciph, buf: make([]byte, maxPacketSize)}
}

type aeadPacketConn struct {
	net.PacketConn
	ciph core.ShadowCipher
	buf  []byte // write scratch, guarded by m
	m    sync.Mutex
}

func (c *aeadPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.m.Lock()
	defer c.m.Unlock()
	buf, err := shadowaead.Pack(c.buf, b, c.ciph)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err // caller-visible n = plaintext length, like upstream
}

func (c *aeadPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := shadowaead.Unpack(b[c.ciph.SaltSize():], b[:n], c.ciph)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}
