package redirect

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	tproxy          bool
	sniffing        bool
	sniffingTimeout time.Duration
}

func (h *redirectHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		tproxy   = "tproxy"
		sniffing = "sniffing"
	)
	h.md.tproxy = mdutil.GetBool(md, tproxy)
	h.md.sniffing = mdutil.GetBool(md, sniffing)
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")
	return
}
