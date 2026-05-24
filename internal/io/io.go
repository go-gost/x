// Package io provides composite IO types that combine separate readers and
// writers into standard [io.ReadWriter] and [io.ReadWriteCloser] pairs, plus
// helpers for half-close and read-deadline propagation.
package io

import (
	"errors"
	"io"
	"time"
)

var (
	// ErrUnsupported is returned when a half-close operation is not supported
	// by the underlying reader or writer.
	ErrUnsupported = errors.New("unsupported")
)

// CloseRead is the interface that groups the basic CloseRead method.
//
// CloseRead closes the read side of a connection. After CloseRead, reads
// return io.EOF while writes remain unaffected. It is typically implemented
// by [net.TCPConn] and connection wrappers throughout the x module.
type CloseRead interface {
	CloseRead() error
}

// CloseWrite is the interface that groups the basic CloseWrite method.
//
// CloseWrite closes the write side of a connection. After CloseWrite, writes
// return an error while reads continue to work. It is typically implemented
// by [net.TCPConn] and connection wrappers throughout the x module.
type CloseWrite interface {
	CloseWrite() error
}

type readWriter struct {
	io.Reader
	io.Writer
}

// NewReadWriter returns an [io.ReadWriter] that reads from r and writes to w.
// The returned value supports [CloseRead] and [CloseWrite] by delegating to
// the corresponding methods on r or w when available.
func NewReadWriter(r io.Reader, w io.Writer) io.ReadWriter {
	return &readWriter{
		Reader: r,
		Writer: w,
	}
}

func (rw *readWriter) CloseRead() error {
	if sc, ok := rw.Reader.(CloseRead); ok {
		return sc.CloseRead()
	}
	if sc, ok := rw.Writer.(CloseRead); ok {
		return sc.CloseRead()
	}
	return ErrUnsupported
}

func (rw *readWriter) CloseWrite() error {
	if sc, ok := rw.Writer.(CloseWrite); ok {
		return sc.CloseWrite()
	}
	if sc, ok := rw.Reader.(CloseWrite); ok {
		return sc.CloseWrite()
	}
	return ErrUnsupported
}

type readWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

// NewReadWriteCloser returns an [io.ReadWriteCloser] that reads from r, writes
// to w, and closes c. Close delegates to c. The returned value also supports
// [CloseRead] and [CloseWrite] by delegating to the corresponding methods on
// r or w when available.
func NewReadWriteCloser(r io.Reader, w io.Writer, c io.Closer) io.ReadWriteCloser {
	return &readWriteCloser{
		Reader: r,
		Writer: w,
		Closer: c,
	}
}

func (rwc *readWriteCloser) CloseRead() error {
	if sc, ok := rwc.Reader.(CloseRead); ok {
		return sc.CloseRead()
	}
	if sc, ok := rwc.Writer.(CloseRead); ok {
		return sc.CloseRead()
	}
	return ErrUnsupported
}

func (rwc *readWriteCloser) CloseWrite() error {
	if sc, ok := rwc.Writer.(CloseWrite); ok {
		return sc.CloseWrite()
	}
	if sc, ok := rwc.Reader.(CloseWrite); ok {
		return sc.CloseWrite()
	}
	return ErrUnsupported
}

type setReadDeadline interface {
	SetReadDeadline(t time.Time) error
}

// SetReadDeadline sets the read deadline on rw if the underlying connection
// supports it. It checks rw itself first, then unwraps *readWriter and
// *readWriteCloser to reach their embedded Reader or Writer. If no
// settable deadline is found the call is a no-op and returns nil.
func SetReadDeadline(rw io.ReadWriter, t time.Time) error {
	if v, _ := rw.(setReadDeadline); v != nil {
		return v.SetReadDeadline(t)
	}
	// Unwrap readWriter/readWriteCloser to reach the underlying connection.
	switch r := rw.(type) {
	case *readWriter:
		if v, _ := r.Reader.(setReadDeadline); v != nil {
			return v.SetReadDeadline(t)
		}
		if v, _ := r.Writer.(setReadDeadline); v != nil {
			return v.SetReadDeadline(t)
		}
	case *readWriteCloser:
		if v, _ := r.Reader.(setReadDeadline); v != nil {
			return v.SetReadDeadline(t)
		}
		if v, _ := r.Writer.(setReadDeadline); v != nil {
			return v.SetReadDeadline(t)
		}
	}
	return nil
}
