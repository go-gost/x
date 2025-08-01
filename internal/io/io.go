package io

import (
	"errors"
	"io"
	"time"
)

var (
	ErrUnsupported = errors.New("unsupported")
)

type CloseRead interface {
	CloseRead() error
}

type CloseWrite interface {
	CloseWrite() error
}

type readWriter struct {
	io.Reader
	io.Writer
}

func NewReadWriter(r io.Reader, w io.Writer) io.ReadWriter {
	return &readWriter{
		Reader: r,
		Writer: w,
	}
}

func (rw *readWriter) CloseRead() error {
	if sc, ok := rw.Writer.(CloseRead); ok {
		return sc.CloseRead()
	}
	return ErrUnsupported
}

func (rw *readWriter) CloseWrite() error {
	if sc, ok := rw.Writer.(CloseWrite); ok {
		return sc.CloseWrite()
	}
	return ErrUnsupported
}

type readWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

func NewReadWriteCloser(r io.Reader, w io.Writer, c io.Closer) io.ReadWriteCloser {
	return &readWriteCloser{
		Reader: r,
		Writer: w,
		Closer: c,
	}
}

func (rwc *readWriteCloser) CloseRead() error {
	if sc, ok := rwc.Writer.(CloseRead); ok {
		return sc.CloseRead()
	}
	return ErrUnsupported
}

func (rwc *readWriteCloser) CloseWrite() error {
	if sc, ok := rwc.Writer.(CloseWrite); ok {
		return sc.CloseWrite()
	}
	return ErrUnsupported
}

type setReadDeadline interface {
	SetReadDeadline(t time.Time) error
}

func SetReadDeadline(rw io.ReadWriter, t time.Time) error {
	if v, _ := rw.(setReadDeadline); v != nil {
		return v.SetReadDeadline(t)
	}
	return nil
}
