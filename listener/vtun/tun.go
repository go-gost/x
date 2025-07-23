package tun

import (
	"io"
	"math"

	"github.com/go-gost/core/logger"
	"golang.zx2c4.com/wireguard/tun"
)

type tunDevice struct {
	dev tun.Device

	packets int
	sizes   []int
	rbufs   [][]byte
	wbufs   [][]byte
	wbuf    []byte

	log logger.Logger
}

func (d *tunDevice) Read(p []byte) (n int, err error) {
	if d.packets > 0 {
		for i, size := range d.sizes {
			if size > 0 {
				n = copy(p, d.rbufs[i][:size])

				d.sizes[i] = 0
				d.packets--
				return
			}
		}
	}

	d.rbufs[0] = p
	packets, err := d.dev.Read(d.rbufs, d.sizes, readOffset)
	if err != nil && err != tun.ErrTooManySegments {
		return
	}
	n = d.sizes[0]

	d.sizes[0] = 0
	d.packets = packets - 1

	// d.log.Debugf("read tun: (%d), % x", n, p[:n])
	return
}

func (d *tunDevice) Write(p []byte) (n int, err error) {
	if writeOffset > 0 {
		copy(d.wbuf[writeOffset:], p)
		d.wbufs[0] = d.wbuf[:writeOffset+len(p)]
	} else {
		d.wbufs[0] = p
	}

	_, err = d.dev.Write(d.wbufs, writeOffset)
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

	batchSize := 16

	rbufs := make([][]byte, batchSize)
	for i := 1; i < len(rbufs); i++ {
		rbufs[i] = make([]byte, math.MaxUint16)
	}

	dev = &tunDevice{
		dev:   ifce,
		sizes: make([]int, batchSize),
		rbufs: rbufs,
		wbufs: make([][]byte, 1),
		wbuf:  make([]byte, math.MaxUint16+writeOffset),
		log:   l.log,
	}
	name, err = ifce.Name()

	return
}
