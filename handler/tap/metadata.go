package tap

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
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

	h.md.key = mdutil.GetString(md, key)
	h.md.bufferSize = mdutil.GetInt(md, bufferSize)
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = 4096
	}
	return
}
