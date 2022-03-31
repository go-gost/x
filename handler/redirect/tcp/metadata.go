package redirect

import (
	mdata "github.com/go-gost/core/metadata"
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
	h.md.sniffing = mdata.GetBool(md, sniffing)
	h.md.tproxy = mdata.GetBool(md, tproxy)
	return
}
