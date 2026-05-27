//go:build !windows

package icmp

import (
	"net"

	"golang.org/x/net/icmp"
)

// ListenPacket listens for ICMP packets on the given network and address.
func ListenPacket(network, address string) (net.PacketConn, error) {
	return icmp.ListenPacket(network, address)
}
