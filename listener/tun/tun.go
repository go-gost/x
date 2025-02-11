package tun

import (
	"io"

	"github.com/go-gost/core/common/bufpool"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunOffsetBytes = 16
)

type tunDevice struct {
	dev            tun.Device
	readBufferSize int
}

func (d *tunDevice) Read(p []byte) (n int, err error) {
	sizes := [1]int{}
	_, err = d.dev.Read([][]byte{p}, sizes[:], 0)
	n = sizes[0]
	return
}

func (d *tunDevice) Write(p []byte) (n int, err error) {
	b := bufpool.Get(tunOffsetBytes + len(p))
	defer bufpool.Put(b)

	copy(b[tunOffsetBytes:], p)
	_, err = d.dev.Write([][]byte{b}, tunOffsetBytes)
	n = len(p)
	return
}

func (d *tunDevice) Close() error {
	return d.dev.Close()
}

func (l *tunListener) createTunDevice() (dev io.ReadWriteCloser, name string, err error) {
	ifce, err := tun.CreateTUN(l.md.config.Name, l.md.config.MTU)
	if err != nil {
		return
	}

	dev = &tunDevice{
		dev:            ifce,
		readBufferSize: l.md.readBufferSize,
	}
	name, err = ifce.Name()

	return
}
