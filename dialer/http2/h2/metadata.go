package h2

import (
	"net/http"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	host   string
	path   string
	header http.Header
}

func (d *h2Dialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host   = "host"
		path   = "path"
		header = "header"
	)

	d.md.host = mdx.GetString(md, host)
	d.md.path = mdx.GetString(md, path)
	if m := mdx.GetStringMapString(md, header); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}
	return
}
