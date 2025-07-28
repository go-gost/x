package tungo

import (
	"io"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	maxBufSize = 16 * 1024
)

type tunDevice struct {
	dev     tun.Device
	packets int
	sizes   []int
	rbufs   [][]byte
	wbufs   [][]byte
	rbuf    []byte
	wbuf    []byte
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

	if readOffset > 0 {
		d.rbufs[0] = d.rbuf
	} else {
		d.rbufs[0] = p
	}

	packets, err := d.dev.Read(d.rbufs, d.sizes, readOffset)
	if err != nil && err != tun.ErrTooManySegments {
		return
	}
	n = d.sizes[0]

	if readOffset > 0 {
		copy(p, d.rbuf[readOffset:n+readOffset])
	}

	d.sizes[0] = 0
	d.packets = packets - 1

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

	batchSize := ifce.BatchSize()

	rbufs := make([][]byte, batchSize)
	for i := 1; i < len(rbufs); i++ {
		rbufs[i] = make([]byte, maxBufSize)
	}

	dev = &tunDevice{
		dev:   ifce,
		sizes: make([]int, batchSize),
		rbufs: rbufs,
		wbufs: make([][]byte, 1),
		rbuf:  make([]byte, maxBufSize+readOffset),
		wbuf:  make([]byte, maxBufSize+writeOffset),
	}
	name, err = ifce.Name()

	return
}
