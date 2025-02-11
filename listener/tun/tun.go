package tun

import (
	"io"
	"math"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunOffsetBytes = 16
	MaxMessageSize = math.MaxUint16
)

type tunDevice struct {
	dev   tun.Device
	elems [][MaxMessageSize]byte
	rbufs [][]byte
	wbuf  [tunOffsetBytes + MaxMessageSize]byte
}

func (d *tunDevice) Read(p []byte) (n int, err error) {
	if len(d.rbufs) > 0 {
		n = copy(p, d.rbufs[0])
		d.rbufs = d.rbufs[1:]
		return
	}

	sizes := make([]int, len(d.elems))
	bufs := make([][]byte, len(d.elems))
	for i := range d.elems {
		bufs[i] = d.elems[i][:]
	}

	nn, err := d.dev.Read(bufs, sizes, 0)
	if err != nil {
		return
	}

	for i := 0; i < nn; i++ {
		if sizes[i] <= 0 {
			continue
		}
		d.rbufs = append(d.rbufs, bufs[i][:sizes[i]])
	}

	n = copy(p, d.rbufs[0])
	d.rbufs = d.rbufs[1:]

	return
}

func (d *tunDevice) Write(p []byte) (n int, err error) {
	buf := d.wbuf[:]
	n = copy(buf[tunOffsetBytes:], p)
	_, err = d.dev.Write([][]byte{buf[:tunOffsetBytes+n]}, tunOffsetBytes)
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
		dev:   ifce,
		elems: make([][MaxMessageSize]byte, ifce.BatchSize()),
	}
	name, err = ifce.Name()

	return
}
