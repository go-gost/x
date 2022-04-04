package tap

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	key        string
	bufferSize int
}

func (h *tapHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key        = "key"
		bufferSize = "bufferSize"
	)

	h.md.key = mdx.GetString(md, key)
	h.md.bufferSize = mdx.GetInt(md, bufferSize)
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = 1500
	}
	return
}
