package com

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultBaudRate = 9600
	defaultParity   = "odd"
)

type metadata struct {
	baudRate int
	parity   string
	timeout  time.Duration
}

func (h *comHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.baudRate = mdutil.GetInt(md, "baud", "com.baud", "handler.com.baud")
	if h.md.baudRate <= 0 {
		h.md.baudRate = defaultBaudRate
	}
	h.md.parity = mdutil.GetString(md, "parity", "com.parity", "handler.com.parity")
	if h.md.parity == "" {
		h.md.parity = defaultParity
	}
	h.md.timeout = mdutil.GetDuration(md, "timeout", "com.timeout", "handler.com.timeout")
	return
}
