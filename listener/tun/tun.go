package tun

import (
	"io"

	"github.com/go-gost/core/common/bufpool"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunOffsetBytes = 4
)

type tunDevice struct {
	dev tun.Device
}

func (d *tunDevice) Read(p []byte) (n int, err error) {
	b := bufpool.Get(tunOffsetBytes + 65535)
	defer bufpool.Put(b)

	n, err = d.dev.Read(*b, tunOffsetBytes)
	if n <= tunOffsetBytes || err != nil {
		d.dev.Flush()
		if n <= tunOffsetBytes {
			err = io.EOF
		}
		return
	}

	n = copy(p, (*b)[tunOffsetBytes:tunOffsetBytes+n])
	return
}

func (d *tunDevice) Write(p []byte) (n int, err error) {
	b := bufpool.Get(tunOffsetBytes + len(p))
	defer bufpool.Put(b)

	copy((*b)[tunOffsetBytes:], p)
	return d.dev.Write(*b, tunOffsetBytes)
}

func (d *tunDevice) Close() error {
	return d.dev.Close()
}

func (l *tunListener) createTunDevice() (dev io.ReadWriteCloser, name string, err error) {
	ifce, err := tun.CreateTUN(l.md.config.Name, l.md.config.MTU)
	if err != nil {
		return
	}

	dev = &tunDevice{dev: ifce}
	name, err = ifce.Name()

	return
}
