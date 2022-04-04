package redirect

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
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
	h.md.sniffing = mdx.GetBool(md, sniffing)
	h.md.tproxy = mdx.GetBool(md, tproxy)
	return
}
