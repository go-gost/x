package io

import "io"

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
