package ss

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	key         string
	readTimeout time.Duration
	bufferSize  int
}

func (h *ssuHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key         = "key"
		readTimeout = "readTimeout"
		bufferSize  = "bufferSize"
	)

	h.md.key = mdutil.GetString(md, key)
	h.md.readTimeout = mdutil.GetDuration(md, readTimeout)

	if bs := mdutil.GetInt(md, bufferSize); bs > 0 {
		h.md.bufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.bufferSize = 4096
	}
	return
}
