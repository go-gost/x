package ss

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBufferSize = 4096
)

type metadata struct {
	key           string
	readTimeout   time.Duration
	udpBufferSize int
}

func (h *ssuHandler) parseMetadata(md mdata.Metadata) (err error) {

	h.md.key = mdutil.GetString(md, "key")
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	h.md.udpBufferSize = mdutil.GetInt(md, "udpBufferSize", "udp.bufferSize")

	return
}
