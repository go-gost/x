package tun

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultKeepAlivePeriod = 10 * time.Second
	defaultBufferSize      = 4096
)

type metadata struct {
	bufferSize      int
	keepAlivePeriod time.Duration
	passphrase      string
}

func (h *tunHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		bufferSize      = "bufferSize"
		keepAlive       = "keepAlive"
		keepAlivePeriod = "ttl"
		passphrase      = "passphrase"
	)

	h.md.bufferSize = mdutil.GetInt(md, bufferSize)
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}

	if mdutil.GetBool(md, keepAlive) {
		h.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if h.md.keepAlivePeriod <= 0 {
			h.md.keepAlivePeriod = defaultKeepAlivePeriod
		}
	}

	h.md.passphrase = mdutil.GetString(md, passphrase)
	return
}
