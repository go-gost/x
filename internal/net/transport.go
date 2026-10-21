package net

import (
	"io"

	"github.com/go-gost/core/common/bufpool"
)

const (
	bufferSize = 64 * 1024
)

// Transport copies data bidirectionally between rw1 and rw2 using two
// goroutines. It waits for both directions to finish and returns the first
// non-EOF error encountered.
//
// It must not return as soon as the first direction is done: the direction
// that finishes first is often the one without an error, and returning early
// would swallow the error of the other direction.
func Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 2)
	go func() {
		errc <- CopyBuffer(rw1, rw2, bufferSize)
	}()

	go func() {
		errc <- CopyBuffer(rw2, rw1, bufferSize)
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil && err != io.EOF && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// CopyBuffer copies from src to dst using a buffer of bufSize obtained from
// the buffer pool, reducing allocation overhead for repeated copies.
func CopyBuffer(dst io.Writer, src io.Reader, bufSize int) error {
	buf := bufpool.Get(bufSize)
	defer bufpool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}
