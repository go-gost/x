package tun

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	bufferSize int
}

func (h *tunHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		bufferSize = "bufferSize"
	)

	h.md.bufferSize = mdx.GetInt(md, bufferSize)
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = 1500
	}
	return
}
