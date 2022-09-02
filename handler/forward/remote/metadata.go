package remote

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	readTimeout time.Duration
}

func (h *forwardHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout = "readTimeout"
	)

	h.md.readTimeout = mdutil.GetDuration(md, readTimeout)
	return
}
