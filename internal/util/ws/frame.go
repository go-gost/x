package ws

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// OpCode represents a WebSocket opcode.
type OpCode int

// https://tools.ietf.org/html/rfc6455#section-11.8.
const (
	OpContinuation OpCode = iota
	OpText
	OpBinary
	// 3 - 7 are reserved for further non-control frames.
	_
	_
	_
	_
	_
	OpClose
	OpPing
	OpPong
	// 11-16 are reserved for further control frames.
)

// FrameHeader represents a WebSocket frame header.
// See https://tools.ietf.org/html/rfc6455#section-5.2.
type FrameHeader struct {
	Fin    bool
	Rsv1   bool
	Rsv2   bool
	Rsv3   bool
	OpCode OpCode

	PayloadLength int64

	Masked  bool
	MaskKey uint32
}

// ReadFrom reads a header from the reader.
// See https://tools.ietf.org/html/rfc6455#section-5.2.
func (h *FrameHeader) ReadFrom(r io.Reader) (n int64, err error) {
	var buf [8]byte

	// First byte. FIN/RSV1/RSV2/RSV3/OpCode(4bits)
	nn, err := io.ReadFull(r, buf[:2])
	n += int64(n)
	if err != nil {
		return
	}

	b := buf[0]
	h.Fin = b&(1<<7) != 0
	h.Rsv1 = b&(1<<6) != 0
	h.Rsv2 = b&(1<<5) != 0
	h.Rsv3 = b&(1<<4) != 0

	h.OpCode = OpCode(b & 0xf)

	b = buf[1]
	h.Masked = b&(1<<7) != 0

	payloadLength := b &^ (1 << 7)
	switch {
	case payloadLength < 126:
		h.PayloadLength = int64(payloadLength)
	case payloadLength == 126:
		nn, err = io.ReadFull(r, buf[:2])
		h.PayloadLength = int64(binary.BigEndian.Uint16(buf[:]))
	case payloadLength == 127:
		nn, err = io.ReadFull(r, buf[:])
		h.PayloadLength = int64(binary.BigEndian.Uint64(buf[:]))
	}
	n += int64(nn)
	if err != nil {
		return
	}

	if h.PayloadLength < 0 {
		err = fmt.Errorf("received negative payload length: %v", h.PayloadLength)
		return
	}

	if h.Masked {
		nn, err = io.ReadFull(r, buf[:4])
		n += int64(nn)
		if err != nil {
			return
		}
		h.MaskKey = binary.LittleEndian.Uint32(buf[:])
	}

	return
}

func (h FrameHeader) Length() int {
	n := 2
	switch {
	case h.PayloadLength > math.MaxUint16:
		n += 8
	case h.PayloadLength > 125:
		n += 2
	}

	if h.Masked {
		n += 4
	}
	return n
}

func (h *FrameHeader) WriteTo(w io.Writer) (n int64, err error) {
	var buf [14]byte
	pos := 0

	var b byte
	if h.Fin {
		b |= 1 << 7
	}
	if h.Rsv1 {
		b |= 1 << 6
	}
	if h.Rsv2 {
		b |= 1 << 5
	}
	if h.Rsv3 {
		b |= 1 << 4
	}

	b |= byte(h.OpCode)

	buf[0] = b

	lengthByte := byte(0)
	if h.Masked {
		lengthByte |= 1 << 7
	}

	switch {
	case h.PayloadLength > math.MaxUint16:
		lengthByte |= 127
	case h.PayloadLength > 125:
		lengthByte |= 126
	case h.PayloadLength >= 0:
		lengthByte |= byte(h.PayloadLength)
	}
	buf[1] = lengthByte
	pos = 2

	switch {
	case h.PayloadLength > math.MaxUint16:
		binary.BigEndian.PutUint64(buf[2:], uint64(h.PayloadLength))
		pos += 8
	case h.PayloadLength > 125:
		binary.BigEndian.PutUint16(buf[2:], uint16(h.PayloadLength))
		pos += 2
	}

	if h.Masked {
		binary.LittleEndian.PutUint32(buf[pos:], h.MaskKey)
		pos += 4
	}

	nn, err := w.Write(buf[:pos])
	n = int64(nn)
	return
}

type Frame struct {
	Header FrameHeader
	Data   io.Reader
}

func (fr *Frame) ReadFrom(r io.Reader) (n int64, err error) {
	if n, err = fr.Header.ReadFrom(r); err != nil {
		return
	}

	fr.Data = io.LimitReader(r, fr.Header.PayloadLength)
	return
}

func (fr *Frame) WriteTo(w io.Writer) (n int64, err error) {
	n, err = fr.Header.WriteTo(w)
	if err != nil {
		return
	}

	nn, err := io.Copy(w, fr.Data)
	n += nn
	return
}
