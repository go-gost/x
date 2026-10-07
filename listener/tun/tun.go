package tun

import (
	"errors"
	"io"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	maxBufSize = 16 * 1024
)

// ErrPacketTooLarge is returned when a packet does not fit the device write
// buffer. Dropping it is the only sane option: the kernel would reject it
// anyway, and reslicing wbuf to fit would panic and take down the process.
//
// It is exported so the p2p hub can tell "one undeliverable datagram" apart
// from a dead device: the former is dropped and counted with the stream left
// up, the latter still tears the stream down.
var ErrPacketTooLarge = errors.New("tun: packet larger than device write buffer")

type tunDevice struct {
	dev     tun.Device
	packets int
	sizes   []int
	rbufs   [][]byte
	wbufs   [][]byte
	rbuf    []byte
	wbuf    []byte
	// maxPacket is the largest packet body the buffers hold. It follows the
	// device MTU (floor maxBufSize): anything bigger is rejected in Write
	// instead of panicking the reslice below.
	maxPacket int
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
	if len(p) > d.maxPacket {
		return 0, ErrPacketTooLarge
	}
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

	return newTunDevice(ifce, l.md.config.MTU)
}

// newTunDevice adapts a tun device to the byte-stream conn this package hands
// out: the device reads and writes packets in batches, the listener speaks
// io.ReadWriteCloser. mtu sizes the packet buffers so a raised tun MTU (jumbo
// UDP) is writable; non-positive mtu keeps the default 16KB buffers.
func newTunDevice(ifce tun.Device, mtu int) (dev io.ReadWriteCloser, name string, err error) {
	batchSize := ifce.BatchSize()

	bufSize := maxBufSize
	if mtu > bufSize {
		bufSize = mtu
	}

	rbufs := make([][]byte, batchSize)
	for i := 1; i < len(rbufs); i++ {
		rbufs[i] = make([]byte, bufSize)
	}

	dev = &tunDevice{
		dev:       ifce,
		sizes:     make([]int, batchSize),
		rbufs:     rbufs,
		wbufs:     make([][]byte, 1),
		rbuf:      make([]byte, bufSize+readOffset),
		wbuf:      make([]byte, bufSize+writeOffset),
		maxPacket: bufSize,
	}
	name, err = ifce.Name()

	return
}
