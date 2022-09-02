package redirect

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	sniffing bool
	tproxy   bool
}

func (h *redirectHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		sniffing = "sniffing"
		tproxy   = "tproxy"
	)
	h.md.sniffing = mdutil.GetBool(md, sniffing)
	h.md.tproxy = mdutil.GetBool(md, tproxy)
	return
}
