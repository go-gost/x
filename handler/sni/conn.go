package sni

import (
	"io"
)

type readWriter struct {
	io.Reader
	io.Writer
}
