package serial

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	timeout time.Duration
}

func (h *serialHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.timeout = mdutil.GetDuration(md, "timeout", "serial.timeout")
	return
}
