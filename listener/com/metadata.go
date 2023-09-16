package com

import (
	"time"

	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultPort     = "COM1"
	defaultBaudRate = 9600
	defaultParity   = "odd"
)

type metadata struct {
	baudRate int
	parity   string
	timeout  time.Duration
}

func (l *comListener) parseMetadata(md md.Metadata) (err error) {
	l.md.baudRate = mdutil.GetInt(md, "baud", "com.baud", "listener.com.baud")
	if l.md.baudRate <= 0 {
		l.md.baudRate = defaultBaudRate
	}
	l.md.parity = mdutil.GetString(md, "parity", "com.parity", "listener.com.parity")
	if l.md.parity == "" {
		l.md.parity = defaultParity
	}
	l.md.timeout = mdutil.GetDuration(md, "timeout", "com.timeout", "listener.com.timeout")
	return
}
