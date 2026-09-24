//go:build android

package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	readOffset  = 0
	writeOffset = 0
)

// createTun adopts the tun device of an Android VpnService. An unprivileged app
// cannot open /dev/net/tun, so the device is created on the Java side
// (VpnService.Builder, which also sets the addresses, routes, MTU and DNS) and
// its fd arrives as the "fd" metadata. That is why nothing here goes through
// netlink, the interface list or resolvectl.
func (l *tunListener) createTun() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	if l.md.fd == nil {
		err = errors.New("tun: no host device fd")
		return
	}

	// The fd belongs to the host and outlives this device, so each device reads
	// from a copy of it: closing the device closes the copy, and a later
	// recreate (an entrypoint restart, a reload) still has a live fd to copy.
	// The provider waits for the VPN to come up, so a start that races it ends
	// up with a device rather than an error.
	src := l.md.fd()
	if src < 0 {
		err = errors.New("tun: no device fd: is the host's VPN up?")
		return
	}
	fd, err := syscall.Dup(src)
	if err != nil {
		err = fmt.Errorf("tun: dup device fd %d: %v", src, err)
		return
	}

	ifce, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		syscall.Close(fd)
		return
	}

	dev, _, err = newTunDevice(ifce)
	if err != nil {
		ifce.Close()
		return
	}

	if len(l.md.config.Net) > 0 {
		ip = l.md.config.Net[0].IP
	}

	return
}
