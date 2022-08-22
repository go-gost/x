package tun

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultKeepAlivePeriod = 10 * time.Second
)

type metadata struct {
	bufferSize      int
	keepAlivePeriod time.Duration
}

func (h *tunHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		bufferSize      = "bufferSize"
		keepAlive       = "keepAlive"
		keepAlivePeriod = "ttl"
	)

	h.md.bufferSize = mdx.GetInt(md, bufferSize)
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = 1500
	}

	if mdx.GetBool(md, keepAlive) {
		h.md.keepAlivePeriod = mdx.GetDuration(md, keepAlivePeriod)
		if h.md.keepAlivePeriod <= 0 {
			h.md.keepAlivePeriod = defaultKeepAlivePeriod
		}
	}
	return
}
