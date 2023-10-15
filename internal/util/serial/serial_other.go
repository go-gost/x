//go:build !windows && !linux
// +build !windows,!linux

package serial

import (
	"errors"
	"time"
)

func openPort(name string, baud int, databits byte, parity Parity, stopbits StopBits, readTimeout time.Duration) (p *Port, err error) {
	return nil, errors.New("unsupported platform")
}

type Port struct {
}

func (p *Port) Read(b []byte) (n int, err error) {
	return
}

func (p *Port) Write(b []byte) (n int, err error) {
	return
}

func (p *Port) Close() (err error) {
	return
}
