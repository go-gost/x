package ss

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	key         string
	readTimeout time.Duration
}

func (h *ssHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key         = "key"
		readTimeout = "readTimeout"
	)

	h.md.key = mdx.GetString(md, key)
	h.md.readTimeout = mdx.GetDuration(md, readTimeout)

	return
}
