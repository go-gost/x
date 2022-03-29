package redirect

import (
	mdata "github.com/go-gost/core/metadata"
)

type metadata struct {
	sniffing bool
}

func (h *redirectHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		sniffing = "sniffing"
	)
	h.md.sniffing = mdata.GetBool(md, sniffing)
	return
}
