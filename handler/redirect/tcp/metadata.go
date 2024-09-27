package redirect

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	readTimeout      time.Duration
	tproxy           bool
	sniffing         bool
	sniffingTimeout  time.Duration
	sniffingFallback bool
}

func (h *redirectHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
	}
	h.md.tproxy = mdutil.GetBool(md, "tproxy")
	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")
	h.md.sniffingFallback = mdutil.GetBool(md, "sniffing.fallback")
	return
}
